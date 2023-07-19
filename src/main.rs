/*
MIT License

Copyright (c) 2023 Yvain Ramora

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/* Importing libraries */
use std::fs;
use std::io::Read;
use std::path::Path;
use std::{env, usize};

/* main function */
fn main() {
    /* retrieves the arguments */
    let args: Vec<String> = env::args().collect();

    /* checks that the file to be dumped is actually given */
    if args.len() < 2 {
        println!("Please specify the name of the NSIS file to be dumped");
        return;
    }

    /* retrieves the name of the file to be dumped */
    let filename = &args[1];

    /* checks that the file exists  */
    let path = Path::new(filename);
    if !path.exists() {
        println!("The {} file does not exist.", filename);
        return;
    }

    /* opens the given file */
    let mut file = match fs::File::open(filename) {
        Ok(file) => file,
        Err(error) => {
            println!("Error opening file: {}", error);
            return;
        }
    };

    /* read the given file */
    let mut contents = Vec::new();
    if let Err(error) = file.read_to_end(&mut contents) {
        println!("Error reading file: {}", error);
        return;
    }

    /* checks that the NSIS signatures are present */
    let index = check_nsis_signatures(&contents);
    if let Some(index) = index {
        println!("NSIS signature found at index {}", index);

        /* retrieves the zip file */
        let mut zip = contents.split_off(index);

        /* checks whether the certificate signature is present */
        let certificate = check_certificate_signature(&zip);
        if let Some(certificate) = certificate {
            println!("certificate signature found at index {}", certificate);

            /* remove the certificate section */
            zip = (&zip[0..certificate - 12]).to_vec()
        }

        /* put the contents of the 7zip in dump.7z */
        match fs::write("dump.7z", patch_7z(&zip)) {
            Ok(_) => println!("The dump.7z file has been successfully created."),
            Err(e) => println!(
                "An error has occurred, the dump.7z file already exists, Error : {}",
                e
            ),
        }
    } else {
        println!("No signature found.");
    }
}

/* NSIS signature verification function */
fn check_nsis_signatures(contents: &[u8]) -> Option<usize> {
    /* store NSIS signatures */
    const SIGNATURES: &[[u8; 16]; 4] = &[
        [
            0xEF, 0xBE, 0xAD, 0xDE, 0x6E, 0x73, 0x69, 0x73, 0x69, 0x6E, 0x73, 0x74, 0x61, 0x6C,
            0x6C, 0x00,
        ],
        [
            0xED, 0xBE, 0xAD, 0xDE, 0x4E, 0x75, 0x6C, 0x6C, 0x53, 0x6F, 0x66, 0x74, 0x49, 0x6E,
            0x73, 0x74,
        ],
        [
            0xEF, 0xBE, 0xAD, 0xDE, 0x4E, 0x75, 0x6C, 0x6C, 0x53, 0x6F, 0x66, 0x74, 0x49, 0x6E,
            0x73, 0x74,
        ],
        [
            0xEF, 0xBE, 0xAD, 0xDE, 0x4E, 0x75, 0x6C, 0x6C, 0x73, 0x6F, 0x66, 0x74, 0x49, 0x6E,
            0x73, 0x74,
        ],
    ];

    /* NSIS detection */
    for (index, chunk) in contents.windows(16).enumerate() {
        for signature in SIGNATURES.iter() {
            if chunk == *signature {
                return Some(index);
            }
        }
    }

    /* return None if no signature is found */
    None
}

/* function to verify the certificate signature */
fn check_certificate_signature(contents: &[u8]) -> Option<usize> {
    /* store NSIS signatures */
    const SIGNATURE: &[u8; 11] = &[
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
    ];

    /* CERTIFICATE detection */
    for (index, chunk) in contents.windows(11).enumerate() {
        if chunk == *SIGNATURE {
            return Some(index);
        }
    }

    /* return None if no signature is found */
    None
}

/* function for patching 7zip by adding 4 bytes (0x00) */
fn patch_7z(contents: &[u8]) -> Vec<u8> {
    /* create an editable copy of the data */
    let mut data = contents.to_vec();

    /* loop to add the 4 bytes (0x00)*/
    for _ in 0..4 {
        data.insert(0, 0x00);
    }

    /* returns the patch bytes from the 7z file */
    return data;
}
