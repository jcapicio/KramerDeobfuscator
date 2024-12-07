from binascii import unhexlify
import subprocess
import re
import argparse
import os

def run_pycdas(input_file):
    pycdas_exe = "pycdas.exe"
    command = [pycdas_exe, input_file]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error running pycdas: {e.stderr}"

def extract_all_load_const_3_contents(bytecode):
    pattern = r"^\s*\d+\s+LOAD_CONST\s+3+:\s+(.+)$"
    matches = re.findall(pattern, bytecode, re.MULTILINE)
    return [match.strip() for match in matches]

def extract_all_load_const_1_contents(bytecode):
    pattern = r"^\s*\d+\s+LOAD_CONST\s+1+:\s+(.+)$"
    matches = re.findall(pattern, bytecode, re.MULTILINE)
    return [match.strip() for match in matches]

def kyrie_decrypt(encrypted_text, key):
    def _decrypt(text, key):
        return "".join(chr(ord(t) - key) if t != "ζ" else "\n" for t in text)
    
    def _dkyrie(text):
        strings = "abcdefghijklmnopqrstuvwxyz0123456789"
        r = ""
        for a in text:
            if a in strings:
                i = strings.index(a) + 1
                if i >= len(strings):
                    i = 0
                a = strings[i]
            r += a
        return r

    decrypted_text = _decrypt(encrypted_text, key)
    return _dkyrie(decrypted_text)

def reverse_kramer_obfuscation(obfuscated_data, key):
    try:
        hex_lines = obfuscated_data.split('/')
        encrypted_lines = [unhexlify(line).decode() for line in hex_lines]
        encrypted_text = "".join(encrypted_lines)
        return kyrie_decrypt(encrypted_text, key)
    except Exception as e:
        return f"An error occurred during decryption: {str(e)}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deobfuscate Kramer.")
    parser.add_argument("-f", "--input_file", required=True, help="Path to the input file for pycdas.")
    args = parser.parse_args()

    input_file = args.input_file
    base_name, ext = os.path.splitext(input_file)
    output_file = f"{base_name}-deobf{ext}"
    
    das = run_pycdas(input_file)
    
    load_const_1_contents = extract_all_load_const_1_contents(das)

    for content in load_const_1_contents:
        pattern = r"\d{4}+"
        matched = re.match(pattern, content)
        if matched:
            key = int(content)
            break
    
    load_const_3_contents = extract_all_load_const_3_contents(das)

    found_deobfuscated_data = False
    for content in load_const_3_contents:
        pattern = r"((.{4}|.{6}|.{8})\/){5}"
        matched = re.search(pattern, content)
        if matched:
            obfuscated_data = content.replace("'", "")
            found_deobfuscated_data = True
            break
    if found_deobfuscated_data:
        deobfuscated_data = reverse_kramer_obfuscation(obfuscated_data, key)
        with open(output_file, "w") as output_file_handle:
            output_file_handle.write(deobfuscated_data)
        
        print(f"Decrypted data written to: {output_file}")
    else:
        print("Did not find obfuscated data. Printing all load_const_3")
        for content in load_const_3_contents:
            print(content)
        print(f"error in {input_file}")
    
