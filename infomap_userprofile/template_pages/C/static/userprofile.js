//
// userprofile.js - helper JS for the userprofile.html page
//
window.addEventListener("load", userprofileStartup);

var pageJSON = JSON.parse(htmlDecode(document.getElementById('page_tags').textContent));

function htmlEncode(value){
    if (value) {
        return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    } else {
        return '';
    }
}

function htmlDecode(s) {
    if (s) {        
            return s.replace(/&quot;/g, '"').replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&');

    } else {
            return '';
    }               
}

function showDiv(id) {
    document.getElementById(id).style.display = "block";
}

function hideDiv(id) {
    document.getElementById(id).style.display = "none";
}

function populateUsername() {
    document.getElementById("usernamediv").textContent = htmlEncode(pageJSON.displayName);
}

function populateAttributesTable() {
    let attrNames = Object.keys(pageJSON.attributes);
    let tbodyRef = document.getElementById('attributesTable').getElementsByTagName('tbody')[0];
    attrNames.sort().forEach((n) => {
        let row = tbodyRef.insertRow();
        let nameCell = row.insertCell();
        let currentValueCell = row.insertCell();
        let newValueCell = row.insertCell();
        nameCell.appendChild(document.createTextNode(n));
        currentValueCell.appendChild(document.createTextNode(pageJSON.attributes[n]));
        let inputField = document.createElement("input");
        inputField.type = "text";
        inputField.id = "input-" + htmlEncode(n);
        inputField.size = "20";
        newValueCell.appendChild(inputField);
    });
}

function doSave() {
    let profileJSON = {};

    let attrNames = Object.keys(pageJSON.attributes);
    attrNames.forEach((n) => {
        let aVal = document.getElementById("input-" + htmlEncode(n)).value;
        if (aVal != null && aVal.length > 0) {
            profileJSON[n] = aVal;
        }
    });

    let attributesForm = document.forms["attributesForm"];
    attributesForm.elements["profileJSON"].value = JSON.stringify(profileJSON);
    attributesForm.submit();
}

function userprofileStartup() {
    populateUsername();
    populateAttributesTable();
    document.getElementById("saveButton").onclick = doSave;
}