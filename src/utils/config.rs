use dotenv::dotenv;
use std::env;

pub struct Config {
    pub proxy_sever_ip: String,
    pub proxy_server_port: String,
    pub db_user: String,
    pub db_pwd: String,
    pub db_ip: String,
    pub db_port: String,
    pub db_name: String,
}

impl Config {
    pub fn new() -> Result<Config, Box<dyn std::error::Error>> {
        // 환경 변수 로드
        dotenv().ok(); // .env 파일의 경로를 지정(기본적으로 루트 폴더 확인)
        
        // 환경 변수에서 값 읽어오기
        let proxy_sever_ip = env::var("PROXY_SERVER_IP").map_err(|_| "PROXY_SERVER_IP must be set")?;
        let proxy_server_port = env::var("PROXY_SERVER_PORT").map_err(|_| "PROXY_SERVER_PORT must be set")?;
        let db_user = env::var("DB_USER").map_err(|_| "DB_USER must be set")?;
        let db_pwd = env::var("DB_PASSWD").map_err(|_| "DB_PASSWD must be set")?;
        let db_ip = env::var("DB_IP").map_err(|_| "DB_IP must be set")?;
        let db_port = env::var("DB_PORT").map_err(|_| "DB_PORT must be set")?;
        let db_name = env::var("DB_NAME").map_err(|_| "DB_NAME must be set")?;

        Ok(Config {
            proxy_sever_ip,
            proxy_server_port,
            db_user,
            db_pwd,
            db_ip,
            db_port,
            db_name,
        })
    }
}