var _fedCMState = {};

function htmlEncode(s) {
	if (s) {
		return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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


function hideDiv(id) {
	document.getElementById(id).style.display = "none";
}

function showDiv(id) {
	document.getElementById(id).style.display = "block";
}

function updateMsg(msg) {
	document.getElementById("msgdiv").innerHTML = htmlEncode(msg);
	showDiv("msgdiv");
}

function doFedCMLogin() {
	
	updateMsg("fedcmrp started")
	
	let providers = [];
	Object.keys(_fedCMState.idpConfig).forEach((p) => {
		providers.push({
				configURL: _fedCMState.idpConfig[p].clientConfigURL,
				clientId: _fedCMState.idpConfig[p].clientID,
				nonce: _fedCMState.nonce			
		});
	});
	
	navigator.credentials.get({
		identity: {
			providers: providers
		}
	}).then((idCred) => {
		let f = document.getElementById('fedcm-form');
		f.token.value = idCred.token;
		f.submit();		
	}).catch((e) => {
		let errStr = ''+e;
		console.log("Error calling FedCM: " + errStr);
		updateMsg(errStr);
	});
}

function startFedCM() {
	if ('IdentityCredential' in window) {
		console.log('FedCM capability is available');
		doFedCMLogin();
		
	} else {
		console.log('FedCM capability not available');
	}	
}

window.addEventListener('load', (event) => {
	_fedCMState = JSON.parse(htmlDecode(document.getElementById('fedcm-tags').innerHTML));
	if (_fedCMState.errorMessage != null) {
		updateMsg(_fedCMState.errorMessage);
	}
	startFedCM();
});
