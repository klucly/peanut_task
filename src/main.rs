use std::env;
mod dependency;

fn main() {
    dotenvy::dotenv().ok();

    let secret_info = env::var("SECRET_INFO")
        .expect(".env is not setup correctly. SECRET_INFO is required to run");

    println!("Secret info: `{}`", secret_info);
    println!("{}", dependency::imported_function());
}