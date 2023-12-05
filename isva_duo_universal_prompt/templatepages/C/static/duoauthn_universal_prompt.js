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

// onLoad function
function loginStartup() {
	// decode the provided macro holder JSON
	let loginPageJSON = JSON.parse(htmlDecode(document.getElementById('duo_login_tags').textContent));
	
	// populate the username
	document.getElementById("usernameDiv").innerHTML = htmlEncode(loginPageJSON.username);
	
	// if there is an error message, display it, otherwise show either the choiceDiv or the pollDiv
	// and kick off polling
	if (document.getElementById("errorDiv") != null && loginPageJSON.errmsg != null) {
		document.getElementById("errorDiv").innerHTML = htmlEncode(loginPageJSON.errmsg);
		showDiv("errorDiv");
	}
}

//
// main action starts here
//

// add event listener for onLoad to call loginStartup
window.addEventListener("load", loginStartup);

