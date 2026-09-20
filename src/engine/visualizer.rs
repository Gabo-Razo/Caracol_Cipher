//! visualizer.rs - Animaciones visuales de cifrado y descifrado Caracol en terminal.
//! Cifrado: Caracol entrando y sellándose en la caja fuerte.
//! Descifrado: Caja abriéndose y caracol invertido saliendo hacia la izquierda.

use std::thread;
use std::time::Duration;

/// Renderiza una secuencia de fotogramas limpiando explícitamente cada línea (\x1b[2K\r)
/// para evitar superposición o "efecto fantasma" entre fotogramas.
fn render_frames(frames: &[&str]) {
    print!("\x1b[?25l"); // Ocultar cursor
    for (i, frame) in frames.iter().enumerate() {
        for line in frame.lines() {
            // \x1b[2K borra la línea completa en la terminal y \r regresa al inicio
            print!("\x1b[2K\r{}\n", line);
        }
        if i < frames.len() - 1 {
            thread::sleep(Duration::from_millis(110));
            print!("\x1b[5A"); // Mover cursor 5 líneas arriba para animar
        }
    }
    print!("\x1b[?25h"); // Restaurar cursor
}

/// Renderiza la animación del caracol ingresando en la caja fuerte (Cifrado / Hide / Seal)
pub fn render_encrypt_animation(dimension: usize, num_decoys: usize) {
    println!("\x1b[1;31m");
    println!("  [SELLANDO EN LABERINTO CARACOL - {}x{} | {} SEÑUELOS]", dimension, dimension, num_decoys);

    let frames: [&str; 4] = [
        // Frame 1: Caracol aproximándose (caja fija a la derecha)
        r#"  .----.   @   @                .--------.
 / .-"-.`.  \v/                /        /|
 | | '\ \ \_/ )         --->  +--------+ |
,-\ `-.' /.'  /               |  [  ]  | /
'---`----'----'               +--------+'"#,

        // Frame 2: Caracol más cerca
        r#"     .----.   @   @             .--------.
    / .-"-.`.  \v/             /        /|
    | | '\ \ \_/ )      --->  +--------+ |
  ,-\ `-.' /.'  /             |  [  ]  | /
 '---`----'----'              +--------+'"#,

        // Frame 3: Caracol entrando al umbral
        r#"       .----.   @   @           .--------.
      / .-"-.`.  \v/           /        /|
      | | '\ \ \_/ )    --->  +--------+ |
    ,-\ `-.' /.'  /           |  [  ]  | /
   '---`----'----'            +--------+'"#,

        // Frame 4: Sellado seguro completo (arte exacto del logo)
        r#"         .----.   @   @         .--------.
        / .-"-.`.  \v/         /        /|
        | | '\ \ \_/ )  --->  +--------+ |
      ,-\ `-.' /.'  /         |  [__]  | /
     '---`----'----'          +--------+'"#,
    ];

    render_frames(&frames);

    println!("\n  \x1b[1;31m[OK] Datos asegurados y dispersados en {} caracoles.\x1b[0m\n", num_decoys + 1);
}

/// Renderiza la animación del caracol saliendo de la caja fuerte (Descifrado / Extract / Open)
pub fn render_decrypt_animation(dimension: usize) {
    println!("\x1b[1;31m");
    println!("  [DESENCRIPTANDO Y EXTRAYENDO CARACOL - {}x{}]", dimension, dimension);

    let frames: [&str; 4] = [
        // Frame 1: Caja cerrada en su posición fija
        r#"                                     .--------.
                                    /        /|
                                   +--------+ |
                                   |  [__]  | /
                                   +--------+'"#,

        // Frame 2: Caja abierta, caracol asomándose
        r#"                 @   @   .----.      .--------.
                  \v/  .'.-"-. \    /        /|
                  ( \_/' / /'  <---+--------+ |
                   \  `./ '.-'/ /-,|  [  ]  | /
                    '----'----`---'+--------+'"#,

        // Frame 3: Caracol invertido saliendo
        r#"             @   @   .----.          .--------.
              \v/  .'.-"-. \        /        /|
              ( \_/' / /' | | <--- +--------+ |
               \  `./ '.-'/ /-,    |  [  ]  | /
                '----'----`---'    +--------+'"#,

        // Frame 4: Caracol completamente liberado hacia la izquierda (arte exacto del usuario)
        r#"         @   @   .----.              .--------.
          \v/  .'.-"-. \            /        /|
          ( \_/' / /' | |    <---  +--------+ |
           \  `./ '.-'/ /-,        |  [__]  | /
            '----'----`---'        +--------+'"#,
    ];

    render_frames(&frames);

    println!("\n  \x1b[1;31m[OK] Laberinto resuelto: Archivo restaurado a su estado original.\x1b[0m\n");
}
