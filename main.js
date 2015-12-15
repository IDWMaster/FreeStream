var Session = require('freespeech-session').Session;
var CleartextServer = require('freespeech-session').CleartextServer;
var crypto = require('freespeech-cryptography');
var fs = require('fs');
var db = require('freespeech-database');
var args = process.argv;
var NodeRSA = crypto.NodeRSA;
if(args.length == 2) {
console.log('USAGE information:\nnode main.js MODE modeArgs');
console.log('MODE can be SERVER, CLIENT, IMPORT, EXPORT, or THUMBPRINT');
console.log('If you are using this program as a server; you must export your public key. To do this; run the command, node main.js EXPORT\nThis will export your public key to stdout, which you can give to clients who wish to connect to this program.');
console.log('If you are running as CLIENT, you must first IMPORT the server\'s public key, by using the command node main.js IMPORT, piping the public key you wish to import to stdin.');
console.log('Once keys have been exchanged, to connect; use the modes listed below\n\n\n');
console.log('node main.js SERVER portno, where portno is the port number to bind to.');
console.log('node main.js CLIENT ipaddr portno thumbprint\nwhere ipaddr is the IP address or hostname you wish to connect to, portno is the port number to connect to, and thumbprint is the thumbprint of the server you are connecting to. You can use the command node main.js THUMBPRINT to find the thumbprint for a public key which is piped to stdin.');
process.exit(0);
}

    var EncryptionKeys;
var startSystem = function(key) {
     switch(args[2]) {
            case 'EXPORT':
                process.stdout.write(key.exportKey('pkcs8-public-der'));
                process.exit(0);
                break;
            case 'IMPORT':
                var ibuffy = new Buffer(0);
                process.stdin.on('end',function(){
                    var nkey = new NodeRSA();
                    nkey.importKey(ibuffy,'pkcs8-public-der');
                    if(!nkey.isPublic(true)) {
                        throw 'Tell whoever sent this to discard their key. They sent their private key instead of public......';
                    }
                    EncryptionKeys.add(nkey,function(success){
                        if(!success) {
                            throw 'Failed to add key to database.';
                        }
                        console.log('Imported key with thumbprint: '+nkey.thumbprint());
                        process.exit(0);
                    });
                });
                process.stdin.on('data',function(blob){
                    ibuffy = Buffer.concat([ibuffy,blob],ibuffy.length+blob.length);
                });
                break;
            case 'SERVER':
                var portno = args[3];
                new CleartextServer(function(port){
                    console.error('Listening on port '+port);
                },function(csession){
                    crypto.negotiateServerConnection(csession,key,function(session){
                        //Start sending from stdin
                        var stream = session.asStream();
                        process.stdin.pipe(stream.write);
                        //Start piping to stdout
                        stream.read.pipe(process.stdout);
                    });
                },portno);
                break;
            case 'CLIENT':
                var server = new CleartextServer(function(port){},function(){});
                var client = server.connect(args[3],args[4]);
                console.error('Connecting....');
                EncryptionKeys.findKey(args[5],function(key){
                  console.error('Found key. Connecting to endpoint.');
                    crypto.connectToEndpoint(client,key,function(session){
                        console.error('Connected to endpoint');
                        var stream = session.asStream();
                        stream.read.pipe(process.stdout);
                        process.stdin.pipe(stream.write);
                        
                    });
                });
                break;
            case 'THUMBPRINT':
                var buffer = new Buffer(0);
                process.stdin.on('data',function(blob){
                    buffer = Buffer.concat([buffer,blob],blob.length+buffer.length);
                });
                process.stdin.on('end',function(){
                    var key = new NodeRSA();
                    key.importKey(buffer,'pkcs8-public-der');
                    console.log(key.thumbprint());
                    process.exit(0);
                });
                break;
        }
}


db.onDbReady(function(){
    EncryptionKeys = db.EncryptionKeys;
    EncryptionKeys.getDefaultKey(function(key){
        if(!key) {
            console.error('Key not found. Generating');
            key = crypto.generateRSAKey(4096);
            console.error('Key generated. Adding to database.');
            EncryptionKeys.add(key,function(success){
                if(success) {
                    startSystem(key);
                    console.error('Key added to database');
                }else {
                    console.error('Failure');
                }
            },true);
        }else {
            startSystem(key);
        }
       
    });
});