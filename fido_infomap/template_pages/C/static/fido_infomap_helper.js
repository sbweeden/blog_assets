// set of client-side helper functions for FIDO capabilities

// assumes availability of jquery and jsrrsasign libraries as includes before this one

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

function getBaseURL() {
    var locationHostPort = location.hostname+(location.port ? ':'+location.port: ''); 
    var baseURL = location.protocol+'//'+locationHostPort;

    return baseURL;
}
