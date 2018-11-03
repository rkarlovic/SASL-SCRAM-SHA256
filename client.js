const net = require('net');
const HmacSHA256 = require('crypto-js/hmac-sha256');
const crypto = require('crypto');


var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex') 
            .slice(0,length);
};

var salting = function(password, nonce, iteration) {
    let Salting = password;
    for (let index = 0; index < iteration; index++) {
        Salting = HmacSHA256(Salting, nonce);
    };
    
    return (Salting.toString());
}

const noncePure = genRandomString(8);
const nonce = Buffer.from(noncePure).toString('base64');
const clientPassword = '12345678';
const serverPassword = 'server123';
const GSPure = 'n';
let GSEncoded = Buffer.from(GSPure).toString('base64');


let msg = {
    GS: GSEncoded,
    order: 1,
    n: 'user',
    r: nonce,
    iteration: null,
    ClientProof: null,
    ServerProof: null,
    status: null
}

var client = new net.Socket();
client.connect(1337, '127.0.0.1', function() {
    console.log('Client connected to server');
    client.write(JSON.stringify(msg));
        
});

client.on('data', function(data) {
    let msg = JSON.parse(data);
    if(msg.order == 2){  
        let iteration = msg.iteration;
        let commonNonceEncoded = msg.r;
        let commonNonce = Buffer.from(commonNonceEncoded, 'base64').toString();
        console.log('Salt: ' + commonNonce);
        let clientProofPure = salting(clientPassword, commonNonce, iteration);
        console.log('Client SHA256 password (ClientProof): ' + clientProofPure);
        let clientProof = Buffer.from(clientProofPure).toString('base64');
        msg.ClientProof = clientProof;
        msg.order = 3;     
        client.write(JSON.stringify(msg));
    }
    if (msg.order == 4) {
        if(msg.status == 'success'){
            console.log('Authentication successful!!!');
            let serverProofEncoded = msg.ServerProof;
            let serverProof = Buffer.from(serverProofEncoded, 'base64').toString();
            let commonNonce = Buffer.from(msg.r, 'base64').toString();
            let iteration = msg.iteration;
            let serverProofClient = salting(serverPassword, commonNonce, iteration);
            console.log('ServerProof (client side): '+ serverProofClient);
            console.log('ServerProof: '+ serverProof);
            if (serverProof == serverProofClient){
                console.log('Authentication of server successful!!!');
            }else{
                console.log('Authentication of server failed!!!');
            }
        }else{
            console.log('Authentication failed!!!');
        }
        
        client.destroy();
    }

});

client.on('close', function() {
	console.log('Connection closed.');
});
