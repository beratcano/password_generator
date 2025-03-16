use anyhow::Result;
use clap::{Parser, Subcommand};
use rand::{thread_rng, Rng};
use rand::seq::SliceRandom;
use rpassword::read_password;
use std::{collections::HashSet, path::PathBuf};

mod storage;
use storage::Storage;

#[derive(Parser, Debug)]
#[command(
    name = "password_generator",
    about = "A secure password generator with encryption capabilities"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new password
    Generate {
        /// Length of the password to generate
        #[arg(short = 'L', long, default_value = "16")]
        length: usize,

        /// Include uppercase letters
        #[arg(short = 'u', long, default_value = "true")]
        uppercase: bool,

        /// Include lowercase letters
        #[arg(short = 'l', long, default_value = "true")]
        lowercase: bool,

        /// Include numbers
        #[arg(short = 'n', long, default_value = "true")]
        numbers: bool,

        /// Include special characters
        #[arg(short = 's', long, default_value = "true")]
        special: bool,

        /// Save the generated password with a label
        #[arg(short = 'S', long)]
        save: bool,

        /// Label for the saved password
        #[arg(short = 'a', long)]
        label: Option<String>,

        /// Associated website
        #[arg(short = 'w', long)]
        website: Option<String>,

        /// Username for the website
        #[arg(short = 'U', long)]
        username: Option<String>,

        /// Additional notes
        #[arg(short = 'N', long)]
        notes: Option<String>,
    },

    /// Initialize a new password store
    Init {
        /// Path to the password store file
        #[arg(short, long)]
        path: Option<PathBuf>,
    },

    /// Save a password to the store
    Save {
        /// Label for the password
        label: String,

        /// The password to save
        #[arg(short, long)]
        password: Option<String>,

        /// Associated website
        #[arg(short = 'w', long)]
        website: Option<String>,

        /// Username for the website
        #[arg(short = 'U', long)]
        username: Option<String>,

        /// Additional notes
        #[arg(short = 'N', long)]
        notes: Option<String>,
    },

    /// Get a password from the store
    Get {
        /// Label of the password to retrieve
        label: String,
    },

    /// List all saved passwords
    List,

    /// Delete a password from the store
    Delete {
        /// Label of the password to delete
        label: String,
    },
}

#[derive(Debug)]
struct PasswordGenerator {
    length: usize,
    char_sets: Vec<&'static str>,
}

impl PasswordGenerator {
    fn new(length: usize) -> Self {
        Self {
            length,
            char_sets: Vec::new(),
        }
    }

    fn with_uppercase(mut self, include: bool) -> Self {
        if include {
            self.char_sets.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        self
    }

    fn with_lowercase(mut self, include: bool) -> Self {
        if include {
            self.char_sets.push("abcdefghijklmnopqrstuvwxyz");
        }
        self
    }

    fn with_numbers(mut self, include: bool) -> Self {
        if include {
            self.char_sets.push("0123456789");
        }
        self
    }

    fn with_special(mut self, include: bool) -> Self {
        if include {
            self.char_sets.push("!@#$%^&*()_+-=[]{}|;:,.<>?");
        }
        self
    }

    fn generate(&self) -> Result<String> {
        if self.char_sets.is_empty() {
            anyhow::bail!("No character sets selected for password generation");
        }

        let mut rng = thread_rng();
        let all_chars: String = self.char_sets.join("");
        let char_vec: Vec<char> = all_chars.chars().collect();

        // Ensure at least one character from each selected set
        let mut password = String::with_capacity(self.length);
        let mut used_sets = HashSet::new();

        while password.len() < self.length {
            let set_idx = rng.gen_range(0..self.char_sets.len());
            let set = self.char_sets[set_idx];
            let char_idx = rng.gen_range(0..set.len());
            let selected_char = set.chars().nth(char_idx).unwrap();
            
            if password.len() < self.char_sets.len() {
                // During initial filling, ensure we use at least one char from each set
                if !used_sets.contains(&set_idx) {
                    password.push(selected_char);
                    used_sets.insert(set_idx);
                }
            } else {
                // After ensuring one from each set, add random chars
                password.push(char_vec[rng.gen_range(0..char_vec.len())]);
            }
        }

        // Shuffle the password to avoid patterns
        let mut password_chars: Vec<char> = password.chars().collect();
        password_chars.shuffle(&mut rng);
        Ok(password_chars.into_iter().collect())
    }
}

fn get_store_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".password_store.json")
}

fn get_master_password() -> Result<String> {
    print!("Enter master password: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    Ok(read_password()?)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            length,
            uppercase,
            lowercase,
            numbers,
            special,
            save,
            label,
            website,
            username,
            notes,
        } => {
            if !uppercase && !lowercase && !numbers && !special {
                anyhow::bail!("At least one character set must be selected");
            }

            let password = PasswordGenerator::new(length)
                .with_uppercase(uppercase)
                .with_lowercase(lowercase)
                .with_numbers(numbers)
                .with_special(special)
                .generate()?;

            println!("Generated password: {}", password);

            if save {
                let label = label.ok_or_else(|| anyhow::anyhow!("Label is required when saving"))?;
                let store = Storage::new(get_store_path());
                let master_password = get_master_password()?;
                store.add_password(label, password, website, username, notes, &master_password)?;
                println!("Password saved successfully!");
            }
        }

        Commands::Init { path } => {
            let store_path = path.unwrap_or_else(get_store_path);
            let store = Storage::new(store_path);
            println!("Enter a master password for the store:");
            let master_password = read_password()?;
            println!("Confirm master password:");
            let confirm_password = read_password()?;

            if master_password != confirm_password {
                anyhow::bail!("Passwords do not match");
            }

            store.init(&master_password)?;
            println!("Password store initialized successfully!");
        }

        Commands::Save {
            label,
            password,
            website,
            username,
            notes,
        } => {
            let store = Storage::new(get_store_path());
            let master_password = get_master_password()?;

            let password = if let Some(pass) = password {
                pass
            } else {
                print!("Enter password to save: ");
                std::io::Write::flush(&mut std::io::stdout())?;
                read_password()?
            };

            store.add_password(label, password, website, username, notes, &master_password)?;
            println!("Password saved successfully!");
        }

        Commands::Get { label } => {
            let store = Storage::new(get_store_path());
            let master_password = get_master_password()?;

            if let Some(entry) = store.get_password(&label, &master_password)? {
                println!("Label: {}", entry.label);
                if let Some(website) = entry.website {
                    println!("Website: {}", website);
                }
                if let Some(username) = entry.username {
                    println!("Username: {}", username);
                }
                if let Some(notes) = entry.notes {
                    println!("Notes: {}", notes);
                }
                println!("Created: {}", entry.created_at);
            } else {
                println!("No password found with label '{}'", label);
            }
        }

        Commands::List => {
            let store = Storage::new(get_store_path());
            let master_password = get_master_password()?;

            let passwords = store.list_passwords(&master_password)?;
            if passwords.is_empty() {
                println!("No passwords stored.");
                return Ok(());
            }

            println!("Stored passwords:");
            for entry in passwords {
                println!("\nLabel: {}", entry.label);
                if let Some(website) = entry.website {
                    println!("Website: {}", website);
                }
                if let Some(username) = entry.username {
                    println!("Username: {}", username);
                }
                println!("Created: {}", entry.created_at);
            }
        }

        Commands::Delete { label } => {
            let store = Storage::new(get_store_path());
            let master_password = get_master_password()?;

            if store.delete_password(&label, &master_password)? {
                println!("Password '{}' deleted successfully", label);
            } else {
                println!("No password found with label '{}'", label);
            }
        }
    }

    Ok(())
}
