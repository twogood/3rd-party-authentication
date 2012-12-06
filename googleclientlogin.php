<?php
require_once 'httplib.php';
#https://www.google.com/accounts/UnlockCaptcha

class GoogleClientLogin {
	function GoogleClientLogin() {
	}
	function Authenticate($username, $password) {
		$params['accountType'] = 'HOSTED_OR_GOOGLE';
		$params['Email'] = $username;
		$params['Passwd'] = $password;
		$params['service'] = 'xapi';
		$params['source'] = 'Zend-ZendFramework';
		$http = new HTTPRequest('https://www.google.com/accounts/ClientLogin');
		$response = $http->Post($params,true);
		$httpdetails = $response['http'];
		$code = $httpdetails['code'];
		if ($code == 200) {
			return true;
		} else {
			return false;
		}
	}
}

?>