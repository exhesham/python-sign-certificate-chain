//The MIT License (MIT)
//
//Copyright (c) 2017 Thunderclouding.com - exhesham
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in
//all copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//THE SOFTWARE.

ca_root=null
ca_intermediate=null
signed_cert=null
key=null

function save_file(filename,text){
	var blob = new Blob([text], {type: "text/plain;charset=utf-8"});
	saveAs(blob, filename);
	
}
function send_sign_req(){
	var c = $('#c').val()
	var cn = $('#cn').val()
	var s = $('#s').val()
	var e = $('#e').val()
	var l = $('#l').val()
	var o = $('#o').val()
	var ou = $('#ou').val()
	if(!c){
		alert('please fill country name')
		return;
	}
	if(!cn){
		alert('please fill common name')
		return;
	}
	data_to_send = {
				'cn':cn,
				'c':c,
				'l':l,
				'e':e,
				's':s,
				'o':o,
				'ou':ou
				
			}
	console.log(data_to_send)
	$.ajax({
	   type: "POST",
	   url: "/sign_ca/sign",
	   dataType: "json",
	   contentType: "application/json",
	   error: function (msg) {
		   alert(msg);
		   location.reload(true);
	   },
	   success: function (data) {
		   if (data) {
			   ca_intermediate=data.ca_inter;
			   ca_root=data.ca_root;
			   signed_cert=data.signed_cert;
			   key=data.key;
			   
			   save_file('signed_cert.key',key)
			   save_file('signed_cert.crt',signed_cert)
			   save_file('ca_root.crt',ca_root)
			   save_file('ca_intermediate.crt',ca_intermediate)
			   // location.reload(true);
		   } else {
			   alert("Cannot add to list !",data);
			   location.reload(true);
		   }
	   },
	   data: JSON.stringify(data_to_send)
	});	
}