//! main.rs - Punto de entrada principal de Caracol Cipher v6 CLI en Rust.
//! Motor criptográfico SPN nativo, esteganografía en recipientes y ancla de sigilo.

mod crypto;
mod engine;
mod carrier;
mod format;
mod cli;

use std::env;
use cli::{
    exec_analyze, exec_extract, exec_hide, exec_keygen, exec_open, exec_seal,
    CliParser, SubCommand,
};

fn print_banner() {
    println!("\x1b[1;31m");
    println!(r#"         .----.   @   @         .--------.
        / .-"-.`.  \v/         /        /|
        | | '\ \ \_/ )  --->  +--------+ |
      ,-\ `-.' /.'  /         |  [__]  | /
     '---`----'----'          +--------+'

  CARACOL CIPHER v6.0"#);
    println!("\x1b[0m");
}

fn print_help() {
    print_banner();
    println!("\x1b[1mUSO:\x1b[0m");
    println!("    caracol <SUBCOMANDO> [OPCIONES]");
    println!("    caracol -a <archivo> [-k clave.key] [-p contraseña]");
    println!();
    println!("\x1b[1;31mSUBCOMANDOS PRINCIPALES:\x1b[0m");
    println!("    \x1b[1;31mkeygen\x1b[0m    Genera una nueva llave privada de 256 bits");
    println!("              -o, --out <ruta.key>        Ruta destino de la llave (defecto: caracol.key)");
    println!();
    println!("    \x1b[1;31manalyze\x1b[0m   Inspección forense de recipientes con Ancla de Sigilo ZKS");
    println!("    \x1b[1;31m-a\x1b[0m        (Atajo directo: caracol -a <archivo> [-k clave.key] [-p contraseña])");
    println!("              -k, --key <clave.key>       Llave privada de 256 bits para autenticación");
    println!("              -p, --passphrase <pass>     Contraseña derivada con PBKDF2 (100k iteraciones)");
    println!();
    println!("    \x1b[1;31mhide\x1b[0m      Cifra y oculta datos dentro de un archivo anfitrión (PDF, PNG, JPG)");
    println!("              -c, --carrier <archivo>     Archivo recipiente donde se inyectará la carga");
    println!("              -i, --in <archivo>          Archivo secreto a ocultar");
    println!("              -t, --text <texto>          Texto secreto directo a ocultar (sin archivo previo)");
    println!("              -o, --out <archivo>         Archivo de salida generado");
    println!("              -k, --key <clave.key>       Llave privada de 256 bits");
    println!("              -p, --passphrase <pass>     Contraseña maestra");
    println!("              -m, --message <mensaje>     Mensaje secreto secundario oculto en cabecera");
    println!("              -v, --visual                Muestra la animación interactiva en terminal");
    println!("              --dim <N>                   Dimensión mínima de matriz NxN (defecto: 128)");
    println!("              --decoys <N>                Número de caracoles señuelo (defecto: 8)");
    println!("              --false-exits <N>           Salidas falsas y trampas por señuelo (defecto: 16)");
    println!();
    println!("    \x1b[1;31mseal\x1b[0m      Cifra en contenedor autónomo .snail v6");
    println!("              -i, --in <archivo>          Archivo de entrada a cifrar");
    println!("              -t, --text <texto>          Texto directo a cifrar");
    println!("              -o, --out <salida.snail>    Ruta del contenedor .snail generado");
    println!("              -k, --key <clave.key>       Llave privada de 256 bits");
    println!("              -p, --passphrase <pass>     Contraseña maestra");
    println!("              -m, --message <mensaje>     Mensaje secreto secundario");
    println!("              -v, --visual                Muestra animación interactiva en terminal");
    println!("              --dim <N>                   Dimensión de la matriz NxN (defecto: 128)");
    println!("              --decoys <N>                Número de señuelos en laberinto (defecto: 8)");
    println!("              --false-exits <N>           Salidas falsas por señuelo (defecto: 16)");
    println!();
    println!("    \x1b[1;31mopen\x1b[0m      Descifra un contenedor autónomo .snail v6");
    println!("              -i, --in <archivo.snail>    Archivo contenedor .snail a abrir");
    println!("              -o, --out <archivo>         Ruta destino (opcional: restaura nombre original)");
    println!("              -k, --key <clave.key>       Llave privada de 256 bits");
    println!("              -p, --passphrase <pass>     Contraseña maestra");
    println!("              -v, --visual                Muestra animación interactiva de descifrado");
    println!("              *(Nota: ¡No requiere conocer --dim, --decoys ni señuelos!)*");
    println!();
    println!("    \x1b[1;31mextract\x1b[0m   Extrae y descifra el contenido oculto en un recipiente");
    println!("              -i, --in <recipiente>       Archivo con carga esteganográfica");
    println!("              -o, --out <archivo>         Ruta de salida (opcional)");
    println!("              -k, --key <clave.key>       Llave privada de 256 bits");
    println!("              -p, --passphrase <pass>     Contraseña maestra");
    println!("              -v, --visual                Muestra animación interactiva de descifrado");
    println!("              *(Nota: ¡No requiere conocer --dim, --decoys ni señuelos!)*");
    println!();
    println!("\x1b[1mEJEMPLOS RÁPIDOS:\x1b[0m");
    println!("    # 1. Crear llave privada");
    println!("    caracol keygen -o mi_llave.key");
    println!();
    println!("    # 2. Cifrar con arquitectura personalizada masiva (matriz 256x256, 32 señuelos, 64 salidas falsas)");
    println!("    caracol seal -t \"Top Secret\" -o laberinto.snail -p mi_clave --dim 256 --decoys 32 --false-exits 64 -v");
    println!();
    println!("    # 3. Descifrar el laberinto gigante (solo necesitas tu clave)");
    println!("    caracol open -i laberinto.snail -p mi_clave -v");
    println!();
    println!("    # 4. Ocultar en PDF con esteganografía sigilosa");
    println!("    caracol hide -c documento.pdf -i secreto.docx -o protegido.pdf -k mi_llave.key -v");
    println!();
    println!("    # 5. Analizar sigilosamente (sin llave no detecta nada)");
    println!("    caracol -a protegido.pdf");
    println!("    caracol -a protegido.pdf -k mi_llave.key");
    println!();
    println!("    # 6. Extraer del recipiente (el PDF original queda intacto)");
    println!("    caracol extract -i protegido.pdf -k mi_llave.key -v");
    println!();
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let cmd = match CliParser::parse(args) {
        Ok(cmd) => cmd,
        Err(err) => {
            eprintln!("\x1b[1;31m[ERROR]\x1b[0m {}", err);
            eprintln!("Ejecuta 'caracol --help' para ver la guía de uso.");
            std::process::exit(1);
        }
    };

    let result = match cmd {
        SubCommand::Keygen { out_path } => exec_keygen(&out_path),
        SubCommand::Analyze {
            target_path,
            key_path,
            passphrase,
        } => exec_analyze(&target_path, key_path.as_deref(), passphrase.as_deref()),
        SubCommand::Hide {
            carrier_path,
            input_path,
            raw_text,
            out_path,
            key_path,
            passphrase,
            hidden_msg,
            dimension,
            decoys,
            false_exits,
            visual,
        } => exec_hide(
            &carrier_path,
            input_path.as_deref(),
            raw_text.as_deref(),
            &out_path,
            key_path.as_deref(),
            passphrase.as_deref(),
            hidden_msg.as_deref(),
            dimension,
            decoys,
            false_exits,
            visual,
        ),
        SubCommand::Extract {
            input_path,
            out_path,
            key_path,
            passphrase,
            visual,
        } => exec_extract(
            &input_path,
            out_path.as_deref(),
            key_path.as_deref(),
            passphrase.as_deref(),
            visual,
        ),
        SubCommand::Seal {
            input_path,
            raw_text,
            out_path,
            key_path,
            passphrase,
            hidden_msg,
            dimension,
            decoys,
            false_exits,
            visual,
        } => exec_seal(
            input_path.as_deref(),
            raw_text.as_deref(),
            out_path.as_deref(),
            key_path.as_deref(),
            passphrase.as_deref(),
            hidden_msg.as_deref(),
            dimension,
            decoys,
            false_exits,
            visual,
        ),
        SubCommand::Open {
            input_path,
            out_path,
            key_path,
            passphrase,
            visual,
        } => exec_open(
            &input_path,
            out_path.as_deref(),
            key_path.as_deref(),
            passphrase.as_deref(),
            visual,
        ),
        SubCommand::Help => {
            print_help();
            Ok(())
        }
        SubCommand::Version => {
            println!("caracol v6.0.0");
            Ok(())
        }
    };


    if let Err(e) = result {
        eprintln!("\x1b[1;31m[ERROR]\x1b[0m {}", e);
        std::process::exit(1);
    }
}
