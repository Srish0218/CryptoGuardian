import streamlit as st
import hashlib

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
            hash_obj = calculate_hash(algo, input_data.encode())
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


# Define input_data outside the "I want to enter data" block


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
