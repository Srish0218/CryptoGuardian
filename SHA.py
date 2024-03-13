import time
import streamlit as st
import hashlib
import matplotlib.pyplot as plt
import numpy as np
import base64


st.set_page_config(
    page_title="CryptoGuardian",
    page_icon="🛡️",
    layout="wide"
)

def perform_hashing(data):
    # Example: Using SHA-256 for hashing
    hashed_value = hashlib.sha256(data.encode()).hexdigest()
    return hashed_value
def generate_hash_results(data):
    # Generate hash results based on the provided data
    # Replace with your actual hash generation code
    hash_results = perform_hashing(data)
    return hash_results

def get_binary_file_downloader_html(bin_file, file_label='File'):
    with open(bin_file, 'rb') as f:
        data = f.read()
    b64 = base64.b64encode(data).decode()
    href = f'<a href="data:application/octet-stream;base64,{b64}" download="{bin_file}" target="_blank">{file_label}</a>'
    return href
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
def create_pie_chart(labels, sizes):
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    ax.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    ax.set_title('Algorithm Distribution')
    return fig
def visualizer(hash_functions , hash_lengths):
    st.markdown("## Visualization")

    c1, c2, c3, c4, c5 = st.columns(5)

    with c1:
        st.markdown("#### Hash Lenghts")
        fig_lengths, ax_lengths = plt.subplots(figsize=(10, 6))
        ax_lengths.plot(hash_functions, hash_lengths, marker='o', label='Hash Lengths')
        ax_lengths.set_ylabel('Hash Length (bits)')
        ax_lengths.set_title('Hash Algorithm Lengths')
        ax_lengths.legend()
        st.pyplot(fig_lengths)

    with c2:
        st.markdown("#### Algorithm Distribution")
        fig_pie = create_pie_chart(hash_functions, hash_lengths)
        st.pyplot(fig_pie)

    with c3:
        st.markdown("Historical Hashing")
        time_points = ["Time 1", "Time 2", "Time 3", "Time 4", "Time 5"]
        hash_values = np.random.rand(len(time_points),
                                     len(hash_functions)) * 1000
        fig_historical, ax_historical = plt.subplots(figsize=(10, 6))
        for i, algo in enumerate(hash_functions):
            ax_historical.plot(time_points, hash_values[:, i], marker='o', label=algo)

        ax_historical.set_ylabel('Hash Values')
        ax_historical.set_title('Historical Hashing Comparison')
        ax_historical.legend()

        # Display the line chart for historical hashing using Streamlit
        st.pyplot(fig_historical)

    with c4:
        st.markdown("Radar Chart")
        # Placeholder data for illustration
        attributes = ['Speed', 'Security', 'Flexibility', 'Collision Resistance']
        hash_functions = ["SHA-256", "SHA-384", "SHA-224", "SHA-512", "SHA-1", "MD5", "SHA3-256", "SHA3-512",
                          "BLAKE2b", "BLAKE2s"]

        # Generate random scores for each algorithm and attribute
        scores = np.random.rand(len(hash_functions), len(attributes))

        # Radar chart for algorithm comparison
        fig_radar, ax_radar = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
        for i, algo in enumerate(hash_functions):
            ax_radar.plot(np.linspace(0, 2 * np.pi, len(attributes), endpoint=False), scores[i], label=algo)
        ax_radar.fill(np.linspace(0, 2 * np.pi, len(attributes), endpoint=False), scores[0], alpha=0.25)

        # Customize chart appearance and labels
        ax_radar.set_xticks(np.linspace(0, 2 * np.pi, len(attributes), endpoint=False))
        ax_radar.set_xticklabels(attributes)
        ax_radar.set_title('Comparison of Hash Algorithms')
        ax_radar.legend()

        # Display the radar chart for algorithm comparison using Streamlit
        st.pyplot(fig_radar)

    with c5:
        st.markdown("Hash Collisions")
        # Generate random collision likelihood scores for each algorithm
        collision_likelihood = np.random.rand(len(hash_functions), len(hash_functions))

        # Heatmap for collision likelihood
        fig_heatmap, ax_heatmap = plt.subplots(figsize=(10, 8))
        heatmap = ax_heatmap.imshow(collision_likelihood, cmap='viridis')

        # Customize chart appearance and labels
        ax_heatmap.set_xticks(np.arange(len(hash_functions)))
        ax_heatmap.set_yticks(np.arange(len(hash_functions)))
        ax_heatmap.set_xticklabels(hash_functions)
        ax_heatmap.set_yticklabels(hash_functions)
        plt.setp(ax_heatmap.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
        ax_heatmap.set_title('Hash Collision Likelihood')
        fig_heatmap.colorbar(heatmap)

        # Display the heatmap for collision likelihood using Streamlit
        st.pyplot(fig_heatmap)



    st.markdown("#### Hash Digests")
    digest_distribution_data = {}
    for hash_algorithm in hash_functions:
        simulated_distribution = np.random.randint(5, 25, size=16)
        digest_distribution_data[hash_algorithm] = simulated_distribution / sum(simulated_distribution) * 100
    for hash_algorithm in hash_functions:
        digest_distribution = digest_distribution_data.get(hash_algorithm, [])
        if len(digest_distribution) == 0:
            continue
        fig, ax = plt.subplots()
        ax.pie(digest_distribution, labels=[f"{i:x}" for i in range(16)], autopct='%1.1f%%', startangle=90,
               colors=plt.cm.tab20c.colors)
    col1, col2 = st.columns(2)
    with col1:
        for algo in hash_functions[5:]:
            with st.expander(algo):
                ax.set_title(f"{hash_algorithm} Digest Distribution")
                st.pyplot(fig)
    with col2:
        for algo in hash_functions[:5]:
            with st.expander(algo):
                ax.set_title(f"{hash_algorithm} Digest Distribution")
                st.pyplot(fig)
def results_for_uploading_file(input_data,hash_functions , hash_lengths):
    st.markdown("#### Hash and Digest Values: ")

    # Hash function selection
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
    visualizer(hash_functions, hash_lengths)
def results_for_string(data, hash_functions , hash_lengths):
    st.markdown("#### Hash and Digest Values: ")
    # Hash function selection
    col1, col2 = st.columns(2)
    with col1:
        for algo in hash_functions[:5]:
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
    with col2:
        for algo in hash_functions[5:]:
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
    visualizer(hash_functions, hash_lengths)


# Streamlit App
st.title("CryptoGuardian 🛡️️")
# SideBar
st.sidebar.header("Get Theory in Detail!!")
with st.sidebar.expander("Visualizations Overview"):
    st.markdown(
        """
    <div class="container-with-border">
    
- **Hash Lengths:** Visualizes the bit lengths of different hash algorithms, providing an understanding of their output sizes.
- **Algorithm Distribution:** Shows the popularity distribution of hash algorithms within the application.
- **Historical Hashing:** Displays changes in hash values over time for each algorithm.
- **Radar Chart:** Compares hash algorithms based on attributes like speed, security, flexibility, and collision resistance.
- **Hash Collisions:** Presents a heatmap indicating the likelihood of collisions between hash algorithms.
- **Hash Digests:** Utilizes doughnut charts to illustrate the distribution of hash digest components for each algorithm.

## Disclaimer
    
The visualizations on this page use a combination of real-world data and simulated data for illustrative purposes. When interpreting the results, keep in mind that actual hash algorithm characteristics may vary based on specific benchmarks and real-world scenarios.
Explore and enjoy the visual journey through the world of hash algorithms with CryptoGuardian!
        </div>   """, unsafe_allow_html=True
    )

with st.sidebar.expander("Overview of Hash Algorithms"):
    st.markdown(
        """
        <div class="container-with-border">


### Overview of Hash Algorithms:

**1. What is a Hash Function?**
A hash function is a mathematical algorithm that takes an input (or 'message') and produces a fixed-size string of characters, which is typically a hash code. The output, or hash, is unique to the input data, and even a small change in the input should result in a significantly different hash.

**2. Purpose of Hash Functions:**
Hash functions serve various purposes, including data integrity verification, digital signatures, password storage, and, notably, in the context of blockchain, ensuring the integrity of blocks and creating unique identifiers for transactions.

### SHA-2 Family:

SHA-2 is a family of hash functions with different bit lengths: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256. The number in each name denotes the length of the hash output in bits.
The SHA (Secure Hash Algorithm) family consists of several hash functions designed by the National Security Agency (NSA) and published by the National Institute of Standards and Technology (NIST). Here's an overview of the commonly used members of the SHA family:

1. **SHA-1 (Secure Hash Algorithm 1):**
   - **Output Size:** 160 bits (20 bytes)
   - **Internal Block Size:** 512 bits (64 bytes)
   - SHA-1 was widely used for cryptographic applications and digital signatures. However, vulnerabilities were discovered, and collision attacks demonstrated its weakness. As a result, SHA-1 is deprecated for cryptographic use, and more secure alternatives are recommended.

2. **SHA-224 (Secure Hash Algorithm 224):**
   - **Output Size:** 224 bits (28 bytes)
   - **Internal Block Size:** 512 bits (64 bytes)
   - SHA-224 is a truncated version of SHA-256, providing a shorter hash value. It is suitable for applications where a shorter hash is needed while maintaining a reasonable level of security.

3. **SHA-256 (Secure Hash Algorithm 256):**
   - **Output Size:** 256 bits (32 bytes)
   - **Internal Block Size:** 512 bits (64 bytes)
   - SHA-256 is part of the SHA-2 family and is widely used in various cryptographic applications, including blockchain technology. It provides a good balance between security and efficiency and is considered secure for most purposes.

4. **SHA-384 (Secure Hash Algorithm 384):**
   - **Output Size:** 384 bits (48 bytes)
   - **Internal Block Size:** 1024 bits (128 bytes)
   - SHA-384 is a truncated version of SHA-512, offering a longer hash value for applications that require increased security. It is commonly used in digital signatures and certificates.

5. **SHA-512 (Secure Hash Algorithm 512):**
   - **Output Size:** 512 bits (64 bytes)
   - **Internal Block Size:** 1024 bits (128 bytes)
   - SHA-512 is another member of the SHA-2 family, providing a higher level of security due to its longer hash size. It is suitable for applications requiring strong cryptographic protection.

**Common Characteristics:**
- All SHA algorithms in the SHA-2 family operate on blocks of data with an internal block size of 512 or 1024 bits.
- The output size of the SHA algorithms can be configured to produce hash values of varying lengths (e.g., SHA-224, SHA-256, SHA-384, SHA-512).

**Usage and Recommendations:**
- SHA-256 is commonly used for various cryptographic applications, including blockchain technology, due to its balance of security and efficiency.
- SHA-3, a separate family of hash functions, is also available and is designed to provide security against certain types of attacks.
- When selecting a SHA algorithm, consider the specific requirements of your application, including the desired level of security and the length of the hash value needed.

### MD Family:

MD5 (Message Digest Algorithm 5) is a widely used cryptographic hash function that produces a 128-bit (16-byte) hash value, typically expressed as a 32-character hexadecimal number. MD5 is part of the MD5 family of hash functions, which includes variants like MD2 and MD4. Here's a brief overview of each member of the MD5 family:

1. **MD2 (Message Digest Algorithm 2):**
   - **Output Size:** 128 bits (16 bytes)
   - **Internal Block Size:** 64 bits (8 bytes)
   - MD2 is an earlier version of the MD family and is considered obsolete due to vulnerabilities. It was designed for 8-bit computers but is not recommended for cryptographic purposes today.

2. **MD4 (Message Digest Algorithm 4):**
   - **Output Size:** 128 bits (16 bytes)
   - **Internal Block Size:** 512 bits (64 bytes)
   - MD4 is another early member of the MD family. It is also considered insecure and has been largely replaced by more secure hash functions. MD4 produces a 128-bit hash value.

3. **MD5 (Message Digest Algorithm 5):**
   - **Output Size:** 128 bits (16 bytes)
   - **Internal Block Size:** 512 bits (64 bytes)
   - MD5 is the most well-known member of the MD family. It was widely used for checksums and integrity verification. However, MD5 is now considered cryptographically broken and unsuitable for further use due to vulnerabilities such as collision attacks.

**Common Characteristics:**
- All three algorithms in the MD5 family produce fixed-size hash values (128 bits or 16 bytes).
- They operate on blocks of data, with different internal block sizes (64 bits for MD2 and MD5, 512 bits for MD4).
- The security of MD2, MD4, and MD5 has been compromised, and they are not recommended for cryptographic applications.

**Usage and Recommendations:**
- While MD2 and MD4 are considered obsolete and insecure, MD5 is still used in non-cryptographic applications, such as checksums for file integrity verification. However, it should not be used for cryptographic purposes where collision resistance is crucial.
- For cryptographic applications and data integrity verification, more secure hash functions like SHA-256 or SHA-3 are recommended.

It's essential to be aware of the limitations and vulnerabilities of MD2, MD4, and MD5 when considering their use in any context. If security is a primary concern, it's advisable to use modern and widely accepted hash functions.

### BLAKE Family:
The BLAKE family of cryptographic hash functions includes BLAKE2b and BLAKE2s, which are successors to the original BLAKE algorithm. Here's an overview of each member of the BLAKE family:

1. **BLAKE (Original Algorithm):**
   - **Output Size:** Configurable (e.g., BLAKE-256, BLAKE-512)
   - **Internal Block Size:** 512 bits (64 bytes)
   - BLAKE is a cryptographic hash function that is not commonly used compared to its successors, BLAKE2b and BLAKE2s. It is based on the HAIFA construction and uses a ChaCha-like permutation. The output size can be configured for different applications.

2. **BLAKE2b (BLAKE2 for Bytes):**
   - **Output Size:** Configurable (up to 64 bytes)
   - **Internal Block Size:** 1024 bits (128 bytes)
   - BLAKE2b is an improved version of BLAKE designed for parallelism and efficiency on 64-bit platforms. It offers high security, speed, and flexibility. BLAKE2b can generate hash values of various lengths, making it suitable for a wide range of applications, including hash-based message authentication codes (HMAC).

3. **BLAKE2s (BLAKE2 for Short):**
   - **Output Size:** Configurable (up to 32 bytes)
   - **Internal Block Size:** 512 bits (64 bytes)
   - BLAKE2s is an optimized version of BLAKE2 designed for 8- and 32-bit platforms. It provides similar security guarantees as BLAKE2b but is more efficient on resource-constrained devices. BLAKE2s is well-suited for applications with limited memory and processing power.

**Common Characteristics:**
- BLAKE and its successors, BLAKE2b and BLAKE2s, are cryptographic hash functions designed to provide high security.
- Both BLAKE2b and BLAKE2s support variable output sizes, allowing users to generate hash values of different lengths.
- BLAKE2b is optimized for 64-bit platforms, while BLAKE2s is optimized for 8- and 32-bit platforms.

**Usage and Recommendations:**
- The BLAKE family, especially BLAKE2b and BLAKE2s, is widely used in various applications, including data integrity verification, digital signatures, and secure communication protocols.
- BLAKE2b and BLAKE2s are considered secure and efficient, making them suitable for a broad range of platforms and use cases.
- BLAKE2 is often chosen for its simplicity, flexibility, and speed, making it a competitive choice among modern cryptographic hash functions.

When selecting a hash function from the BLAKE family, the choice between BLAKE2b and BLAKE2s depends on the platform and specific requirements of the application. Both variants offer strong security and performance characteristics.
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
     </div>   """, unsafe_allow_html=True
    )




Feature = st.selectbox("What do you want to do:", ("Hashing Data", "Compare Hashing"))

if Feature == "Hashing Data":
    method = st.selectbox("Select method", ("I want to enter data", "I want to upload file"))
    hash_functions = ["SHA-256", "SHA-384", "SHA-224", "SHA-512", "SHA-1", "MD5", "SHA3-256", "SHA3-512", "BLAKE2b",
                      "BLAKE2s"]
    hash_lengths = [256, 384, 224, 512, 160, 128, 256, 512, 512, 256]

    if method == "I want to enter data":
        # Input string
        input_data = st.text_area("Enter Data:")
        if st.button("Generate Hash"):
            if input_data:
                # Generate hash results
                hash_results = generate_hash_results(input_data)
                # Display hash results
                results_for_string(hash_results , hash_functions , hash_lengths)
            else:
                st.error("Please enter data before generating hash.")

    elif method == "I want to upload file":
        label = "Choose a file"
        uploaded_file = st.file_uploader(label)
        if uploaded_file is not None:
            data = uploaded_file.read()
            if st.button("Generate Hash"):
                results_for_uploading_file(data , hash_functions , hash_lengths)
                if st.button("Download Hash Results"):
                    # Generate hash results
                    # Save results to a file (e.g., CSV, JSON, etc.)
                    # Replace 'results_file.csv' with the actual file name
                    results_file = 'results_file.csv'
                    # Provide a download link for the results file
                    st.markdown(get_binary_file_downloader_html(results_file, 'Download Results'),
                                unsafe_allow_html=True)

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
            width: 100%;
            max-height: 500px; /* Set the maximum height for the container */
            overflow-y: auto; /* Add vertical scroll if content exceeds the maximum height */
            border: 1px solid #ddd;
            border-radius: 5px;
        }
    </style>
""", unsafe_allow_html=True)

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
