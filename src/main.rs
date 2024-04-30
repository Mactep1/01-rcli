use clap::Parser;
use rcli::{
    process_csv, process_decode, process_encode, process_genpass, process_http_serve,
    process_text_generate, process_text_sign, process_text_verify, Base64SubCommand,
    HttpSubCommand, Opts, SubCommand,
};
use std::fs;
use zxcvbn::zxcvbn;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let opts: Opts = Opts::parse();
    match opts.cmd {
        SubCommand::Csv(opts) => {
            let output = if let Some(output) = opts.output {
                output.clone()
            } else {
                format!("output.{}", opts.format)
            };
            process_csv(&opts.input, output, opts.format)?;
        }

        SubCommand::GenPass(opts) => {
            let password = process_genpass(
                opts.length,
                opts.uppercase,
                opts.lowercase,
                opts.number,
                opts.symbol,
            )?;
            println!("{}", password);

            let estimate = zxcvbn(&password, &[])?;
            eprintln!("Password strength: {}", estimate.score());
        }

        SubCommand::Base64(subcmd) => match subcmd {
            Base64SubCommand::Encode(opts) => {
                let encoded = process_encode(&opts.input, opts.format)?;
                println!("{}", encoded);
            }
            Base64SubCommand::Decode(opts) => {
                let decoded = process_decode(&opts.input, opts.format)?;

                // TODO: decoded dataa might not be string(but for this example, we assume it is string)
                let decoded = String::from_utf8(decoded)?;
                println!("{}", decoded);
            }
        },

        SubCommand::Text(subcmd) => match subcmd {
            rcli::TextSubCommand::Sign(opts) => {
                let sig = process_text_sign(&opts.input, &opts.key, opts.format)?;
                println!("{}", sig);
            }
            rcli::TextSubCommand::Verify(opts) => {
                let verified =
                    process_text_verify(&opts.input, &opts.key, &opts.signature, opts.format)?;
                println!("{}", verified);
            }
            rcli::TextSubCommand::Generate(opts) => {
                let key = process_text_generate(opts.format)?;
                match opts.format {
                    rcli::TextSignFormat::Blake3 => {
                        let name = opts.output.join("blake3.key");
                        fs::write(name, &key[0])?;
                    }
                    rcli::TextSignFormat::Ed25519 => {
                        let name = &opts.output;
                        fs::write(name.join("ed25519.sk"), &key[0])?;
                        fs::write(name.join("ed25519.pk"), &key[1])?;
                    }
                }
                println!("{:?}", key);
            }
        },

        SubCommand::Http(subcmd) => match subcmd {
            HttpSubCommand::Serve(opts) => {
                process_http_serve(opts.dir, opts.port).await?;
            }
        },
    }

    Ok(())
}
