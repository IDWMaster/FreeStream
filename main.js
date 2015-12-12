var NodeRSA = require('node-rsa');

NodeRSA.prototype.thumbprint = function () {
    var pubbin = this.exportKey('pkcs8-public-der');
    var hash = crypto.createHash('sha256');
    hash.update(pubbin);
    return hash.digest('hex');
};
var Session = require('freespeech-session').Session;
var CleartextServer = require('freespeech-session').CleartextServer;
var crypto = require('freespeech-cryptography');
var fs = require('fs');
var db = require('freespeech-database');
var args = process.argv;
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

db.onDbReady(function(){
    var EncryptionKeys = db.EncryptionKeys;
    EncryptionKeys.getDefaultKey(function(key){
        if(!key) {
            key = crypto.generateRSAKey(4096);
            EncryptionKeys.add(key,function(){
                
            },true);
        }
        switch(args[2]) {
            case 'EXPORT':
                process.stdout.write(key.exportKey('pkcs8-public-der'));
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
                    crypt.negotiateServerConnection(csession,key,function(session){
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
                EncryptionKeys.findKey(args[5],function(key){
                    crypto.connectToEndpoint(client,key,function(session){
                        var stream = session.asStream();
                        stream.read.pipe(process.stdout);
                        process.stdin.pipe(stream.write);
                        
                    });
                });
                break;
        }
    });
});