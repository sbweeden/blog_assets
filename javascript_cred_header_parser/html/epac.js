// utility functions
function htmlEncode(value){
    if (value) {
        let converter = document.createElement('p');
        converter.textContent = value;
        return converter.innerHTML;
    } else {
        return '';
    }
}


function hideDiv(id) {
	document.getElementById(id).style.display = "none";
}

function showDiv(id) {
	document.getElementById(id).style.display = "block";
}

function showError(msg) {
	document.getElementById("errorDiv").innerHTML = htmlEncode(msg);
	showDiv("errorDiv");
}

function clearError() {
	hideDiv("errorDiv");
	document.getElementById("errorDiv").innerHTML = "";
}

function clearCreds() {
	hideDiv("credsDiv");
	document.getElementById("usernameDiv").innerHTML = "";
	document.getElementById("credTableBody").innerHTML = "";
}

function populateRow(row, name, value) {
	borderTD = row.insertCell();
	nameTD = row.insertCell();
	valueTD = row.insertCell();
	
	borderTD.style = "background-color:#4178BE;width: 8px;padding:0px";
	
	nameTD.style = "border: none; border-top: 1px solid #CCCCCC; border-bottom: 1px solid #CCCCCC; padding:10px";
	nameTD.innerHTML = htmlEncode(name);
	
	valueTD.style = "border: none; border-top: 1px solid #CCCCCC; border-bottom: 1px solid #CCCCCC; padding:10px";
	if (Array.isArray(value) && value.length > 1) {
		let valueStr = "";
		for (let i = 0; i < value.length; i++) {
			valueStr += "["+i+"] " + htmlEncode(value[i]) + "<br />";
		}
		valueTD.innerHTML = valueStr;
	} else {
		valueTD.innerHTML = htmlEncode(Array.isArray(value) ? value[0] : value);
	}
}

function displayCreds(stsuu) {
	document.getElementById("usernameDiv").innerHTML = htmlEncode(stsuu.Principal["name"]);
	
	Object.keys(stsuu.AttributeList).sort().forEach((k) => {
		// insert a row for this attribute
		let r = document.getElementById("credTableBody").insertRow();
		r.style = "height:40px";
		populateRow(r, k, stsuu.AttributeList[k]);
	});	
	showDiv("credsDiv");
}

// this will also be used by the credparser.js for debug output
function debugLog(s) {
	console.log(s);
}

function showEPAC() {
	// clear any existing table and error
	clearCreds();
	clearError();
	
	// get epac value from form
	let epacVal = document.getElementById("epac").value;
	if (epacVal != null && epacVal.length > 0) {
		let stsuu = null;
		try {
			stsuu = decodePACHeader(epacVal);
		} catch (e) {
			debugLog("Caught exception parsing epac: " + e);
			stsuu = null;
		}
		if (stsuu == null || Object.keys(stsuu.Principal).length == 0) {
			showError("Unable to decode PAC value");
		} else {
			debugLog("stsuu: " + JSON.stringify(stsuu));
			displayCreds(stsuu);
		}
	} else {
		// ignore if no value
	}
}

function pageLoad() {
	// add event handler for button click
	document.getElementById("displayEPACButton").addEventListener("click", showEPAC);	
}

//
// main action starts here
//

// add event listener for page load
window.addEventListener("load", pageLoad);



