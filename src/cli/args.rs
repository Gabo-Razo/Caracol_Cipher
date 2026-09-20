//! args.rs - Analizador de argumentos de línea de comandos sin dependencias externas.
//! Soporta subcomandos y banderas cortas y largas (-a, -k, -c, -i, -o, etc.)

#[derive(Debug, PartialEq)]
pub enum SubCommand {
    Keygen {
        out_path: String,
    },
    Analyze {
        target_path: String,
        key_path: Option<String>,
        passphrase: Option<String>,
    },
    Hide {
        carrier_path: String,
        input_path: Option<String>,
        raw_text: Option<String>,
        out_path: String,
        key_path: Option<String>,
        passphrase: Option<String>,
        hidden_msg: Option<String>,
        dimension: usize,
        decoys: usize,
        false_exits: usize,
        visual: bool,
    },
    Extract {
        input_path: String,
        out_path: Option<String>,
        key_path: Option<String>,
        passphrase: Option<String>,
        visual: bool,
    },
    Seal {
        input_path: Option<String>,
        raw_text: Option<String>,
        out_path: Option<String>,
        key_path: Option<String>,
        passphrase: Option<String>,
        hidden_msg: Option<String>,
        dimension: usize,
        decoys: usize,
        false_exits: usize,
        visual: bool,
    },
    Open {
        input_path: String,
        out_path: Option<String>,
        key_path: Option<String>,
        passphrase: Option<String>,
        visual: bool,
    },
    Help,
    Version,
}

pub struct CliParser;

impl CliParser {
    pub fn parse(args: Vec<String>) -> Result<SubCommand, String> {
        if args.len() <= 1 {
            return Ok(SubCommand::Help);
        }

        let first = &args[1];

        // Atajo especial solicitado: caracol -a <archivo> [-k <clave>]
        if first == "-a" || first == "--analyze" {
            return Self::parse_analyze_shortcut(&args[2..]);
        }

        match first.as_str() {
            "keygen" => Self::parse_keygen(&args[2..]),
            "analyze" => Self::parse_analyze(&args[2..]),
            "hide" | "embed" => Self::parse_hide(&args[2..]),
            "extract" => Self::parse_extract(&args[2..]),
            "seal" => Self::parse_seal(&args[2..]),
            "open" => Self::parse_open(&args[2..]),
            "--help" | "-h" | "help" => Ok(SubCommand::Help),
            "--version" | "-v" | "version" => Ok(SubCommand::Version),
            unknown => Err(format!("Subcomando desconocido: '{}'. Ejecuta 'caracol help' para ver las opciones.", unknown)),
        }
    }

    fn parse_keygen(args: &[String]) -> Result<SubCommand, String> {
        let mut out_path = "caracol.key".to_string();
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-o" | "--out" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("Falta la ruta para -o / --out".to_string());
                    }
                    out_path = args[i].clone();
                }
                _ => {}
            }
            i += 1;
        }
        Ok(SubCommand::Keygen { out_path })
    }

    fn parse_analyze_shortcut(args: &[String]) -> Result<SubCommand, String> {
        if args.is_empty() {
            return Err("Uso: caracol -a <archivo> [-k clave.key] [-p contraseña]".to_string());
        }

        let target_path = args[0].clone();
        let mut key_path = None;
        let mut passphrase = None;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "-k" | "--key" => {
                    i += 1;
                    if i < args.len() {
                        key_path = Some(args[i].clone());
                    }
                }
                "-p" | "--passphrase" => {
                    i += 1;
                    if i < args.len() {
                        passphrase = Some(args[i].clone());
                    }
                }
                _ => {}
            }
            i += 1;
        }

        Ok(SubCommand::Analyze {
            target_path,
            key_path,
            passphrase,
        })
    }

    fn parse_analyze(args: &[String]) -> Result<SubCommand, String> {
        let mut target_path = None;
        let mut key_path = None;
        let mut passphrase = None;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-i" | "--in" => {
                    i += 1;
                    if i < args.len() {
                        target_path = Some(args[i].clone());
                    }
                }
                "-k" | "--key" => {
                    i += 1;
                    if i < args.len() {
                        key_path = Some(args[i].clone());
                    }
                }
                "-p" | "--passphrase" => {
                    i += 1;
                    if i < args.len() {
                        passphrase = Some(args[i].clone());
                    }
                }
                arg if !arg.starts_with('-') && target_path.is_none() => {
                    target_path = Some(arg.to_string());
                }
                _ => {}
            }
            i += 1;
        }

        let target = target_path.ok_or_else(|| "Debe especificar el archivo a analizar: caracol analyze <archivo>".to_string())?;

        Ok(SubCommand::Analyze {
            target_path: target,
            key_path,
            passphrase,
        })
    }

    fn parse_hide(args: &[String]) -> Result<SubCommand, String> {
        let mut carrier_path = None;
        let mut input_path = None;
        let mut raw_text = None;
        let mut out_path = None;
        let mut key_path = None;
        let mut passphrase = None;
        let mut hidden_msg = None;
        let mut dimension = 128;
        let mut decoys = 8;
        let mut false_exits = 16;
        let mut visual = false;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-c" | "--carrier" => {
                    i += 1;
                    if i < args.len() { carrier_path = Some(args[i].clone()); }
                }
                "-i" | "--in" => {
                    i += 1;
                    if i < args.len() { input_path = Some(args[i].clone()); }
                }
                "-t" | "--text" => {
                    i += 1;
                    if i < args.len() { raw_text = Some(args[i].clone()); }
                }
                "-o" | "--out" => {
                    i += 1;
                    if i < args.len() { out_path = Some(args[i].clone()); }
                }
                "-k" | "--key" => {
                    i += 1;
                    if i < args.len() { key_path = Some(args[i].clone()); }
                }
                "-p" | "--passphrase" => {
                    i += 1;
                    if i < args.len() { passphrase = Some(args[i].clone()); }
                }
                "-m" | "--message" => {
                    i += 1;
                    if i < args.len() { hidden_msg = Some(args[i].clone()); }
                }
                "-v" | "--visual" => {
                    visual = true;
                }
                "--dim" => {
                    i += 1;
                    if i < args.len() { dimension = args[i].parse().unwrap_or(128); }
                }
                "--decoys" => {
                    i += 1;
                    if i < args.len() { decoys = args[i].parse().unwrap_or(8); }
                }
                "--false-exits" | "--exits" => {
                    i += 1;
                    if i < args.len() { false_exits = args[i].parse().unwrap_or(16); }
                }
                _ => {}
            }
            i += 1;
        }

        let carrier = carrier_path.ok_or_else(|| "Falta especificar el archivo recipiente (-c <recipiente.pdf>)".to_string())?;
        if input_path.is_none() && raw_text.is_none() {
            return Err("Falta especificar el contenido: use -i <archivo> o -t <texto>".to_string());
        }
        let out = out_path.unwrap_or_else(|| format!("protegido_{}", carrier));

        Ok(SubCommand::Hide {
            carrier_path: carrier,
            input_path,
            raw_text,
            out_path: out,
            key_path,
            passphrase,
            hidden_msg,
            dimension,
            decoys,
            false_exits,
            visual,
        })
    }

    fn parse_extract(args: &[String]) -> Result<SubCommand, String> {
        let mut input_path = None;
        let mut out_path = None;
        let mut key_path = None;
        let mut passphrase = None;
        let mut visual = false;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-i" | "--in" => {
                    i += 1;
                    if i < args.len() { input_path = Some(args[i].clone()); }
                }
                "-o" | "--out" => {
                    i += 1;
                    if i < args.len() { out_path = Some(args[i].clone()); }
                }
                "-k" | "--key" => {
                    i += 1;
                    if i < args.len() { key_path = Some(args[i].clone()); }
                }
                "-p" | "--passphrase" => {
                    i += 1;
                    if i < args.len() { passphrase = Some(args[i].clone()); }
                }
                "-v" | "--visual" => {
                    visual = true;
                }
                arg if !arg.starts_with('-') && input_path.is_none() => {
                    input_path = Some(arg.to_string());
                }
                _ => {}
            }
            i += 1;
        }

        let input = input_path.ok_or_else(|| "Falta especificar el archivo de entrada (-i <archivo>)".to_string())?;

        Ok(SubCommand::Extract {
            input_path: input,
            out_path,
            key_path,
            passphrase,
            visual,
        })
    }

    fn parse_seal(args: &[String]) -> Result<SubCommand, String> {
        let mut input_path = None;
        let mut raw_text = None;
        let mut out_path = None;
        let mut key_path = None;
        let mut passphrase = None;
        let mut hidden_msg = None;
        let mut dimension = 128;
        let mut decoys = 8;
        let mut false_exits = 16;
        let mut visual = false;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-i" | "--in" => {
                    i += 1;
                    if i < args.len() { input_path = Some(args[i].clone()); }
                }
                "-t" | "--text" => {
                    i += 1;
                    if i < args.len() { raw_text = Some(args[i].clone()); }
                }
                "-o" | "--out" => {
                    i += 1;
                    if i < args.len() { out_path = Some(args[i].clone()); }
                }
                "-k" | "--key" => {
                    i += 1;
                    if i < args.len() { key_path = Some(args[i].clone()); }
                }
                "-p" | "--passphrase" => {
                    i += 1;
                    if i < args.len() { passphrase = Some(args[i].clone()); }
                }
                "-m" | "--message" => {
                    i += 1;
                    if i < args.len() { hidden_msg = Some(args[i].clone()); }
                }
                "-v" | "--visual" => {
                    visual = true;
                }
                "--dim" => {
                    i += 1;
                    if i < args.len() { dimension = args[i].parse().unwrap_or(128); }
                }
                "--decoys" => {
                    i += 1;
                    if i < args.len() { decoys = args[i].parse().unwrap_or(8); }
                }
                "--false-exits" | "--exits" => {
                    i += 1;
                    if i < args.len() { false_exits = args[i].parse().unwrap_or(16); }
                }
                arg if !arg.starts_with('-') && input_path.is_none() => {
                    input_path = Some(arg.to_string());
                }
                _ => {}
            }
            i += 1;
        }

        if input_path.is_none() && raw_text.is_none() {
            return Err("Falta especificar el contenido: use -i <archivo> o -t <texto>".to_string());
        }

        Ok(SubCommand::Seal {
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
        })
    }

    fn parse_open(args: &[String]) -> Result<SubCommand, String> {
        let mut input_path = None;
        let mut out_path = None;
        let mut key_path = None;
        let mut passphrase = None;
        let mut visual = false;

        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "-i" | "--in" => {
                    i += 1;
                    if i < args.len() { input_path = Some(args[i].clone()); }
                }
                "-o" | "--out" => {
                    i += 1;
                    if i < args.len() { out_path = Some(args[i].clone()); }
                }
                "-k" | "--key" => {
                    i += 1;
                    if i < args.len() { key_path = Some(args[i].clone()); }
                }
                "-p" | "--passphrase" => {
                    i += 1;
                    if i < args.len() { passphrase = Some(args[i].clone()); }
                }
                "-v" | "--visual" => {
                    visual = true;
                }
                arg if !arg.starts_with('-') && input_path.is_none() => {
                    input_path = Some(arg.to_string());
                }
                _ => {}
            }
            i += 1;
        }

        let input = input_path.ok_or_else(|| "Falta especificar el archivo de entrada (-i <archivo.snail>)".to_string())?;

        Ok(SubCommand::Open {
            input_path: input,
            out_path,
            key_path,
            passphrase,
            visual,
        })
    }
}

