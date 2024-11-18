mod utils;

use anyhow::Result;
use chrono::Local;
use log::{error, info};
use mysql::{prelude::Queryable, serde_json, Opts, Pool};
use redis::Commands;
use tokio::{io::{AsyncReadExt as _, AsyncWriteExt as _}, sync::Mutex, select};
use urlencoding::encode;
use base64::prelude::*;
use std::{collections::BTreeMap, error::Error, net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use utils::config::Config;

#[derive(Debug)]
struct TargetInfo {
    ip: String,
    port: String,
    // function_codes: Vec<String>,
}

// redis 연결 공유
type RedisConn = Arc<Mutex<redis::Connection>>;

// 접속하고자 하는 타겟 정보 조회
async fn get_target_info(pool: &Arc<Pool>) -> Result<TargetInfo, Box<dyn Error + Send + Sync>> {
    let mut conn= pool.get_conn()?;

    let query = "SELECT ip, port FROM device WHERE status = 'ON' ORDER BY id ASC";

    // let query = r#"
    //     SELECT d.ip, d.port, p.function_code
    //     FROM device d
    //     JOIN policy p ON d.policy_id = p.id
    //     WHERE d.status = 'ON'
    //     ORDER BY d.id ASC
    // "#;

    let res: Option<(String, String)> = conn.query_first(query)?;

    // TODO : 여기에서 정책정보도 동시에 같이 가져오기???

    if let Some((ip, port)) = res {
        let target_info = TargetInfo {ip, port};
        Ok(target_info)
    } else {
        Err("No activate device found".into())
    }
}

// protocol 종류 확인
fn check_protocol(packet: &[u8]) -> &'static str {
    match packet.len() {
        len if len > 7 => { // Modbus 최소 8비트
            // Modbus protocol ID (2바이트): \x00\x00
            let protocol_id = u16::from_be_bytes([packet[2], packet[3]]);
            match protocol_id {
                0 => "MODBUS",
                _ => "UNKNOWN",
            }
        },
        _ => "TCP",
    }
}

// Modbus 패킷을 검사하여 정책에 따른 허용 여부 확인(true: 허용, false: 거부)
fn is_request_allowed(packet: &[u8]) -> bool {
    // TODO : 이 부분에서 device별 function_code 확인해서 허가 받지 않는 function_code인경우 차단 할필요있음(지금은 write 5,6,15,16차단)
   info!("modbus 패킷 확인 : {:?}", packet);

   let function_code = packet[7];

    match function_code {
        0x05 | 0x06 | 0x0f | 0x10 => false, // write 5, 6, 15, 16
        _ => true,
    }
}

// redis에 저장
async fn save_to_redis(redis_conn: RedisConn, client_addr: SocketAddr, target_ip: String, target_port: String, protocol: &str, allow: &bool, packet_data: &[u8]) -> Result<(), redis::RedisError> {
    let mut map = BTreeMap::new();

    let src_ip = client_addr.ip().to_string();
    let src_port = client_addr.port().to_string();
    let protocol = protocol.to_string();
    let allow = allow.to_string();
    let data = packet_data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<String>>().join(" ");
    let datetime = Local::now().to_string();

    map.insert("src_ip", src_ip.clone());
    map.insert("src_port", src_port.clone());
    map.insert("dst_ip", target_ip.clone());
    map.insert("dst_port", target_port.clone());
    map.insert("protocol", protocol.clone());
    map.insert("allow", allow.clone());
    map.insert("data", data.clone());
    map.insert("datetime", datetime.clone());

    let mut conn = redis_conn.lock().await;

    // Redis 스트림에 데이터 추가
    let _ = conn.xadd_map("modbus_stream", "*", map)?;

    // JSON 형식으로 변환하여 Pub/Sub 채널에 데이터 게시
    let json_data = serde_json::json!({
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": target_ip,
        "dst_port": target_port,
        "protocol": protocol,
        "allow": allow,
        "data": BASE64_STANDARD.encode(packet_data),
        "datetime": datetime
    }).to_string();

    info!("json 데이터 확인 : {}", json_data);

    conn.publish("modbus_events", json_data)?;

    Ok(())
}

async fn handle_client(mut client: TcpStream, redis_conn: RedisConn, client_addr: SocketAddr, target_info: TargetInfo) -> Result<()> {
    let tcp_addr = format!("{}:{}", target_info.ip.clone(), target_info.port.clone());
    let mut target_server = TcpStream::connect(tcp_addr).await?;

    let (mut ri, mut wi) = client.split();
    let (mut ro, mut wo) = target_server.split();

    loop {
        let mut client_buf = vec![0u8; 1024];
        let mut server_buf = vec![0u8; 1024];

        select! {
            // 클라이언트 -> 서버로 데이터 전송 처리
            result = ri.read(&mut client_buf) => {
                match result {
                    Ok(0) => {
                        info!("Client closed connection");
                        break;
                    }
                    Ok(n) => {
                        let packet_data = client_buf[..n].to_vec();

                        // protocol 종류 확인
                        let protocol = check_protocol(&packet_data);

                        // 정책 확인
                        let allow = match protocol {
                            "MODBUS" => is_request_allowed(&packet_data),
                            "TCP" => true, // tcp 일단 모두 허용
                            _ => false,
                        };

                        let redis_conn = redis_conn.clone();
                        let target_ip = target_info.ip.clone();
                        let target_port = target_info.port.clone();

                        // redis에 패킷 데이터 일부 저장
                        if let Err(e) = save_to_redis(redis_conn, client_addr, target_ip, target_port, &protocol, &allow, &packet_data).await {
                            error!("Failed to save to Redis: {}", e);
                        }

                        // 정책에 따른 허가가 날 경우 타겟 서버에 전달
                        if allow {
                            if let Err(e) = wo.write_all(&client_buf[..n]).await {
                                error!("Failed to write to server: {}", e);
                                break;
                            }
                        } else {
                            info!("Request denied according to policy");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error reading from client: {}", e);
                        break;
                    }
                }
            }
            // 서버 -> 클라이언트로 데이터 전송 처리
            result = ro.read(&mut server_buf) => {
                match result {
                    Ok(0) => {
                        info!("Server closed connection");
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = wi.write_all(&server_buf[..n]).await {
                            error!("Failed to write to client: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error reading from server: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 로깅
    if let Err(e) = log4rs::init_file("log4rs.yml", Default::default()){
        println!("logging error: {}", e)
    }

    let cfg: Config = match Config::new() {
        Ok(cfg) => cfg,
        Err(e) => {
            error!(".env file load error : {}", e);
            panic!()
        }
    };

    // db connection
    let encode_pwd = encode(&cfg.db_pwd);
    let db_url = format!("mysql://{}:{}@{}:{}/{}", cfg.db_user, encode_pwd, cfg.db_ip, cfg.db_port, cfg.db_name);
    let opts: Opts = match Opts::from_url(&db_url) {
        Ok(opts) => opts,
        Err(e) => {
            error!("db connection fail : {:?}", e);
            panic!()
        }
    };
    let pool = Pool::new(opts)?;
    let pool = Arc::new(pool);

    // redis connection
    let redis_client = redis::Client::open("redis://127.0.0.1:6379/0")?;
    let redis_conn = Arc::new(Mutex::new(redis_client.get_connection()?));

    let proxy_addr = format!("{}:{}", cfg.proxy_sever_ip, cfg.proxy_server_port);


    // 프록시 서버 IP 및 포트 설정
    let listener = TcpListener::bind(proxy_addr).await?;

    info!("proxy server listening...");

    loop {
        match listener.accept().await {
            Ok((socket, client_addr)) => {
                info!("Client connected from {}", client_addr);

                let pool: Arc<Pool> = pool.clone();
                let redis_conn = redis_conn.clone();

                // 새로운 클라이언트 연결 시마다 별도의 task에서 처리
                tokio::spawn(async move {
                    match get_target_info(&pool).await {
                        Ok(target_info) => {
                            if let Err(e) = handle_client(socket, redis_conn, client_addr, target_info).await {
                                error!("Error handling client: {:?}", e);
                            }
                        }
                        Err(e) => error!("접속하고자 하는 device 정보가 없습니다: {:?}", e),
                    }
                });
            }
            Err(e) => error!("Incoming conection error {}", e)
        }
    }
}
