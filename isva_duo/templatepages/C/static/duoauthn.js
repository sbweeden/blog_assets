// utility variables
var locationHostPort = location.hostname+(location.port ? ':'+location.port: '');
var baseURL = location.protocol+'//'+locationHostPort;
var pollTime = 2000; // msec

// utility functions
function htmlEncode(value){
    if (value != null) {
        return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    } else {
        return '';
    }
}

function htmlDecode(s) {
    if (s != null) {        
            return s.replace(/&quot;/g, '"').replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&');

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

function updatePollTimestamp(status) {
	let nowStr = (new Date()).toUTCString();
	document.getElementById("pollTimestamp").innerText = nowStr;
	document.getElementById("pollStatus").innerText = status;
}

function buildPollURL() {
	let result = document.getElementById("loginform").action;
	if (result.indexOf("apiauthsvc") < 0) {
		result = result.replace("/authsvc/", "/apiauthsvc/");
	}                
	return result;
}

function poll() {
	ajaxActive = true; 	
	let url = buildPollURL();
	console.log("polling: " + url);

	fetch(
		url,
		{
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json'
			},
			body: JSON.stringify({
				operation: "verify",
				txnId: document.getElementById("txnId").value,
				completeAuthn: "false"
			})
		}
	).then((response) => {
		if (!response.ok) {
			throw new Error("Unexpected HTTP response code: " + response.status);
		}
		return response.json();
	}).then((data) => {
		data.loginJSON = JSON.parse(htmlDecode(data.loginJSON));
		console.log("Received poll data: " + JSON.stringify(data));

		// first update the form action
		document.getElementById('loginform').action = data.action.replace("/apiauthsvc/", "/authsvc/");

		// if the lastTxnStatus is "allow", then its time to post the form directing the browser to complete login
		if (data.loginJSON.lastTxnStatus == "allow") {
			document.getElementById('loginform').submit();
		} else {
			// if we were denied, show that as an error, otherwise update
			// the displayed status and start a new timer to re-poll
			if (data.loginJSON.lastTxnStatus == "deny") {
				hideDiv("contentDiv");
				document.getElementById("errorDiv").innerHTML = "Request denied";
				showDiv("errorDiv");
			} else {
				// update the last poll information on the browser
				updatePollTimestamp(data.loginJSON.lastTxnStatus);
				window.setTimeout(poll, pollTime);
			}
		}
	}).catch((error) => {
		console.log(error);
		let errStr = "";
		if (typeof error == "object" && error["message"] != null) {
			errStr = error.message;
		} else {
			errStr = error;
		}
		document.getElementById("errorDiv").innerHTML = htmlEncode(errStr);
		showDiv("errorDiv");
	});
}

// onLoad function
function loginStartup() {
	// decode the provided macro holder JSON
	let loginPageJSON = JSON.parse(htmlDecode(document.getElementById('duo_login_tags').textContent));
	
	// populate the username and transactionId if present
	document.getElementById("usernameDiv").innerHTML = htmlEncode(loginPageJSON.username);
	if (loginPageJSON["txnId"] != null) {
		document.getElementById("txnId").value = htmlEncode(loginPageJSON.txnId);
	}

	// populate the poll timestamp
	updatePollTimestamp(loginPageJSON["lastTxnStatus"]);
	
	// if there is an error message, display it, otherwise show the contentDiv
	// and kick off polling
	if (loginPageJSON.errmsg != null) {
		document.getElementById("errorDiv").innerHTML = htmlEncode(loginPageJSON.errmsg);
		showDiv("errorDiv");
	} else {
		showDiv("contentDiv");
		window.setTimeout(poll, pollTime);
	}
}

//
// main action starts here
//

// add event listener for onLoad to call loginStartup
window.addEventListener("load", loginStartup);

