// Embute as migrations no binário (`sqlx::migrate!`). Sem esta linha o Cargo
// não recompila quando só um .sql muda, e o binário subiria sem a migration nova.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
