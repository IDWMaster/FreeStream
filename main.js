var args = process.argv;
if(args.length == 1) {
console.log('USAGE information:\nnode main.js MODE modeArgs');
console.log('MODE can be SERVER, CLIENT, IMPORT, EXPORT, or THUMBPRINT');
console.log('If you are using this program as a server; you must export your public key. To do this; run the command, node main.js EXPORT\nThis will export your public key to stdout, which you can give to clients who wish to connect to this program.');
console.log('If you are running as CLIENT, you must first IMPORT the server\'s public key, by using the command node main.js IMPORT, piping the public key you wish to import to stdin.');
console.log('Once keys have been exchanged, to connect; use the modes listed below\n\n\n');
console.log('node main.js SERVER portno, where portno is the port number to bind to.');
console.log('node main.js CLIENT ipaddr portno thumbprint\nwhere ipaddr is the IP address or hostname you wish to connect to, portno is the port number to connect to, and thumbprint is the thumbprint of the server you are connecting to. You can use the command node main.js THUMBPRINT to find the thumbprint for a public key which is piped to stdin.');
return;
}

for(var i = 0;i<args.length;i++) {

}
