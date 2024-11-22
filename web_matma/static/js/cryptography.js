var letters = [
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z"
];
var option = document.getElementById("algorithm-option");
var choiceOption = document.getElementById("choice-option");
var keyOption = document.getElementById("key-option");
var bitOption = document.getElementById("bit-option");
var eccOption = document.getElementById("ecc-option");

var inputField = document.getElementById("input");
var shiftInputDiv = document.getElementById("shift-input-div");
var shiftInputField = document.getElementById("shift-input");
var shiftInputLabel = document.getElementById("shift-input-label");
var inputLabel = document.getElementById("input-label");

var output = document.getElementById("output");
var enterBtn = document.getElementById("enter-btn");
var encrypt = document.getElementById("encrypt");
var decrypt = document.getElementById("decrypt");

var public_key = document.getElementById("public-key");
var private_key = document.getElementById("private-key");
const generate = document.getElementById("generate");

// Mozilla Reload Bug Fix
keyOption.value = "rsa_key";
bitOption.value = "1024";
option.value = "rsa_al";
choiceOption.value = "encrypt";
eccOption.style.visibility = "hidden";
eccOption.value = "ecc_256"

keyOption.addEventListener("change", e => {
    var selectedOption = keyOption.value;
    if (selectedOption === "ecc_key") {
        // Ẩn phần tử bitOption mà không thay đổi vị trí bằng cách sử dụng visibility
        bitOption.style.visibility = "hidden";
        eccOption.style.visibility = "visible";
    } else {
        // Hiển thị lại phần tử bitOption
        bitOption.style.visibility = "visible";
        eccOption.style.visibility = "hidden";
        // eccOption.style.display = "block";
    }
});

generate.addEventListener("click", () => {
    var selectedOption = keyOption.value;
    if (selectedOption !== "ecc_key") {
        generate_cryptosystem_key(keyOption.value, bitOption.value)
    } else {
        generate_cryptosystem_key(keyOption.value, eccOption.value)
    }
    // generate_cryptosystem_key(keyOption.value, bitOption.value)
});

function generate_cryptosystem_key(keyValue, bitValue) {
    // console.log(keyValue, bitValue, `${window.location.origin}/generate_cryptosystem_key/?key=${encodeURIComponent(keyValue)}&bit=${encodeURIComponent(bitValue)}`)
    fetch(`${window.location.origin}/generate_cryptosystem_key/?key=${encodeURIComponent(keyValue)}&bit=${encodeURIComponent(bitValue)}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);  // Nếu HTTP không thành công
            }
            return response.json();
        })
        .then(result => {
            if (result.error) {
                throw new Error(result.error); // Nếu có lỗi, ném ngoại lệ
            }
            // console.log(result)
            // console.log(`/generate_cryptosystem_key/?key=${encodeURIComponent(keyValue)}&bit=${encodeURIComponent(bitValue)}`);

            if (public_key) {
                public_key.innerHTML = result.public_key.slice(2, -3)
            }
            if (private_key) {
                private_key.innerHTML = result.private_key.slice(2, -3)
            }
            // console.log(result.public_key, result.private_key)
            return result; // Trả về kết quả nếu thành công
        })
        .catch(error => {
            console.error('Error:', error);
            throw error; // Để báo lỗi cho hàm gọi
        });
}

choiceOption.addEventListener("change", e => {
    const selectedOption = choiceOption.value;
    // console.log(selectedOption)

    if (selectedOption === "encrypt") {
        shiftInputLabel.textContent = "Public key:";
        inputLabel.textContent = "Plaintext:";
        enterBtn.textContent = "Encrypt";

    } else if (selectedOption === "decrypt") {
        shiftInputLabel.textContent = "Private key:";
        inputLabel.textContent = "CipherText:";
        enterBtn.textContent = "Decrypt";
    }
});


enterBtn.addEventListener("click", () => {
    var choice = choiceOption.value;
    var algorithm = option.value;
    var text = inputField.value;
    var key = "b'" + shiftInputField.value + "\n'";
    if (
        !inputField.value.replace(/\s/g, "").length ||
        !shiftInputField.value.replace(/\s/g, "").length
    ) {
        alert("Please Fill In The Required Fields");
    } else {
        // console.log(choice, algorithm, text, key);
        // console.log(compressKey(key));
        fetch(`${window.location.origin}/en_de_algorithm/?choice=${encodeURIComponent(choice)}&al=${encodeURIComponent(algorithm)}&text=${encodeURIComponent(text)}&key=${encodeURIComponent(String(key))}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);  // Nếu HTTP không thành công
                }
                return response.json();
            })
            .then(result => {
                if (result.error) {
                    throw new Error(result.error); // Nếu có lỗi, ném ngoại lệ
                }

                output.innerHTML = result.output
                // console.log(result)
                return result; // Trả về kết quả nếu thành công
            })
            .catch(error => {
                console.error('Error:', error);
                throw error; // Để báo lỗi cho hàm gọi
            });
    }
});


// inputField.addEventListener("keypress", e => {
//     var key = e.keyCode || e.charCode;
//     if (
//         (key >= 65 && key <= 90) ||
//         (key >= 97 && key <= 122) ||
//         key == 8 ||
//         key == 32
//     ) {
//         return true;
//     } else {
//         alert("Data can only contain alpahbetical characters");
//         e.preventDefault();
//     }
// });

// shiftInputField.addEventListener("keypress", e => {
//     var key = e.keyCode || e.charCode;
//     if (key >= 48 && key <= 57) {
//         return true;
//     } else {
//         alert("Shift Value is supposed to be number");
//         e.preventDefault();
//     }
// });

// xử lý cuộn xuống đúng phần encrypt, decrypt
// Lấy các nút và phần tử terminal
const terminal = document.getElementById('terminal');

const geneKey = document.getElementById("gene-key");

// Gắn sự kiện click cho từng nút

generate.addEventListener('click', () => {
    geneKey.scrollIntoView({ behavior: 'smooth', block: 'start' });
});

