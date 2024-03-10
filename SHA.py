import streamlit as st
import hashlib
st.set_page_config(layout="wide")


def calculate_hash(hash_function, data):
    if hash_function == "SHA-256":
        return hashlib.sha256(data)
    elif hash_function == "SHA-384":
        return hashlib.sha384(data)
    elif hash_function == "SHA-224":
        return hashlib.sha224(data)
    elif hash_function == "SHA-512":
        return hashlib.sha512(data)
    elif hash_function == "SHA-1":
        return hashlib.sha1(data)
    elif hash_function == "MD5":
        return hashlib.md5(data)
    elif hash_function == "SHA3-256":
        return hashlib.sha3_256(data)
    elif hash_function == "SHA3-512":
        return hashlib.sha3_512(data)
    elif hash_function == "BLAKE2b":
        return hashlib.blake2b(data)
    elif hash_function == "BLAKE2s":
        return hashlib.blake2s(data)

def results_for_uploading_file(input_data):
    # Hash function selection
    hash_functions = ["SHA-256", "SHA-384", "SHA-224", "SHA-512", "SHA-1", "MD5", "SHA3-256", "SHA3-512", "BLAKE2b", "BLAKE2s"]
    for algo in hash_functions:
        with st.expander(algo):
            hash_obj = calculate_hash(algo, input_data)
            hashed_value = hash_obj.hexdigest()
            st.write(f"{algo} Hex Hash:")
            st.info(hashed_value)

            try:
                # Attempt to use the digest() method for algorithms that support it
                hash_digest = hash_obj.digest()
                st.write(f"{algo} Digest: ")
                st.info(hash_digest)
            except AttributeError:
                # For algorithms that don't support digest(), display a warning
                st.warning(f"{algo} Digest: Not supported!!!")

def results_for_string(data):
    # Hash function selection
    hash_functions = ["SHA-256", "SHA-384", "SHA-224", "SHA-512", "SHA-1", "MD5", "SHA3-256", "SHA3-512", "BLAKE2b",
                      "BLAKE2s"]
    for algo in hash_functions:
        with st.expander(algo):
            hash_obj = calculate_hash(algo, data.encode())  # Fix: use 'data' instead of 'input_data'
            hashed_value = hash_obj.hexdigest()
            st.write(f"{algo} Hex Hash:")
            st.info(hashed_value)

            try:
                # Attempt to use the digest() method for algorithms that support it
                hash_digest = hash_obj.digest()
                st.write(f"{algo} Digest: ")
                st.info(hash_digest)
            except AttributeError:
                # For algorithms that don't support digest(), display a warning
                st.warning(f"{algo} Digest: Not supported!!!")



# Streamlit App
st.title("CryptoGuardian 🛡️️")

Feature = st.selectbox("What do you want to do:" , ("Hashing Data" , "Compare Hashing"))

if Feature == "Hashing Data":
    method = st.selectbox("Select method", ("I want to enter data", "I want to upload file"))

    if method == "I want to enter data":
        # Input string
        input_data = st.text_area("Enter Data:")
        if st.button("Generate Hash"):
            if input_data:
                results_for_string( input_data)

    elif method == "I want to upload file":
        label = "Choose a file"
        uploaded_file = st.file_uploader(label)
        if uploaded_file is not None:
            data = uploaded_file.read()
            if st.button("Generate Hash"):
                results_for_uploading_file(data)

elif Feature == "Compare Hashing":
        st.text("Enter two hash values to compare:")
        hash1 = st.text_input("Hash 1:")
        hash2 = st.text_input("Hash 2:")
        if st.button("Compare"):
            if hash1 and hash2:
                if hash1 == hash2:
                    st.success("Hashes match! Data integrity is preserved.")
                else:
                    st.error("Hashes do not match! Data integrity may be compromised.")


st.markdown("""
    <style>
        .container-with-border {
            padding: 10px;
            width: 85%;
            max-height: 250px; /* Set the maximum height for the container */
            overflow-y: auto; /* Add vertical scroll if content exceeds the maximum height */
            border: 1px solid #ddd;
            border-radius: 5px;
        }
    </style>
""", unsafe_allow_html=True)

# Define input_data outside the "I want to enter data" block
if st.checkbox("Get Theory in Detail!!"):
    st.markdown(
        """
        <div class="container-with-border">
        

### Overview of Secure Hash Algorithms (SHA):

**1. What is a Hash Function?**
A hash function is a mathematical algorithm that takes an input (or 'message') and produces a fixed-size string of characters, which is typically a hash code. The output, or hash, is unique to the input data, and even a small change in the input should result in a significantly different hash.

**2. Purpose of Hash Functions:**
Hash functions serve various purposes, including data integrity verification, digital signatures, password storage, and, notably, in the context of blockchain, ensuring the integrity of blocks and creating unique identifiers for transactions.

### SHA-2 Family:

SHA-2 is a family of hash functions with different bit lengths: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256. The number in each name denotes the length of the hash output in bits.

**1. SHA-256:**
   - Output Size: 256 bits
   - Internal Block Size: 32 bits
   - It is widely used in blockchain technology, providing a balance between security and efficiency.

**2. SHA-384:**
   - Output Size: 384 bits
   - Internal Block Size: 32 bits
   - Truncated version of SHA-512, often used in digital signatures and certificates.

**3. SHA-224:**
   - Output Size: 224 bits
   - Internal Block Size: 32 bits
   - A truncated version of SHA-256, designed for applications with limited space.

**4. SHA-512:**
   - Output Size: 512 bits
   - Internal Block Size: 64 bits
   - Offers a higher level of security, often used in critical applications.

### SHA-1 (Included for Comparison):

**SHA-1:**
   - Output Size: 160 bits
   - Internal Block Size: 32 bits
   - Deprecated due to vulnerabilities; should not be used for cryptographic purposes.

### Hashing Process:

1. **Encoding:**
   - Before hashing, the input data is encoded into bytes. In the provided Python code, `str1.encode()` converts the string "Krish Naik1" into bytes.

2. **Hash Calculation:**
   - The hash object, such as `hashlib.sha256()`, is initialized with the encoded data.
   - The `update()` method can be used for incremental updates, but in this example, it's not necessary.

3. **Hexadecimal Representation:**
   - The `hexdigest()` method converts the binary hash into a human-readable hexadecimal representation.

### Use Cases:

- **Blockchain:**
  - In blockchain technology, SHA-256 is commonly used to create unique identifiers (hashes) for blocks.
  - The deterministic nature of hash functions ensures that a block's hash changes if any information in the block is modified, maintaining the integrity of the blockchain.

- **Data Integrity:**
  - Hash functions are used to verify the integrity of transmitted or stored data. The recipient can recompute the hash and check if it matches the original hash.

- **Digital Signatures:**
  - Hash functions are an integral part of digital signatures, providing a compact representation of data that is signed for verification purposes.

In summary, Secure Hash Algorithms play a crucial role in ensuring data integrity, security, and uniqueness in various applications, with SHA-256 being a fundamental component in blockchain technology.
     </div>   """ , unsafe_allow_html=True
    )


footer = """<style>
a:link , a:visited{
color: black;
font-weight: bold;
background-color: transparent;
text-decoration: underline;
}

a:hover,  a:active {
color: red;
background-color: transparent;
text-decoration: underline;
}


.footer a {
    color: #007bff;
    text-decoration: none;
    font-weight: bold;
}
.footer {
position: fixed;
left: 0;
bottom: 0;
width: 100%;
background-color: dark grey;
color: white;
text-align: center;
}
</style>
<div class="footer">
<p>Developed with ❤ by <a style='display: block; text-align: center;' href="https://github.com/Srish0218" target="_blank">Srishti Jaitly 🌸</a></p>
</div>
"""
st.markdown(footer, unsafe_allow_html=True)
