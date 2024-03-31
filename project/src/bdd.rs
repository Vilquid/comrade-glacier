// use diesel::pg::PgConnection;
// use diesel::prelude::*;
// use dotenv::dotenv;
// use std::env;
// // use crate::model::Port;
// 
// pub fn establish_connection() -> PgConnection
// {
// 	dotenv().ok();
// 
// 	let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
// 	PgConnection::establish(&database_url)
// 		.unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
// }
// 
// pub fn add_port(conn: &mut PgConnection, data: Port) -> Port
// {
// 	// use crate::schema::posts;
// 
// 	// let new_post = NewPost { title, body };
// 
// 	// diesel::insert_into(posts::table)
// 	// 	.values(&new_post)
// 	// 	.returning(Post::as_returning())
// 	// 	.get_result(conn)
// 	// 	.expect("Error saving new post")
// }
// 
