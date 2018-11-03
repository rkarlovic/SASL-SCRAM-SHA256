const net = require('net');
const HmacSHA256 = require('crypto-js/hmac-sha256');
const crypto = require('crypto');



var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex') 
            .slice(0,length);
};

const nonce = genRandomString(8);
const password = '12345678';
const serverPassword = 'server123';

function salting(password, nonce, iteration) {
    let Salting = password;
    for (let index = 0; index < iteration; index++) {
        Salting = HmacSHA256(Salting, nonce);
    };    
    return (Salting.toString());
}

const server = net.createServer()

server.on("connection", (socket) => {
    
    const dataTimeOut = (msg) => setTimeout(() => {
        socket.write(JSON.stringify(msg));
    }, 2000);

    socket.on("error", (err) =>{
    console.log("Policy server socket error: ");
    console.log(err.stack);
    });

    socket.setEncoding("utf8");
    socket.on("data", (data) => {
        const msg = JSON.parse(data);
        const GSHeader = Buffer.from(msg.GS, 'base64').toString();
        if (GSHeader != null && msg.order == 1) {
            let noncePure = Buffer.from(msg.r, 'base64').toString();
            let nonceMerge = noncePure.concat(nonce);
            let nonceEncoded = Buffer.from(nonceMerge).toString('base64');
            msg.r = nonceEncoded;
            let iteration = (Math.floor(Math.random() * 20) + 1);
            msg.iteration = iteration;
            msg.order = 2;
            dataTimeOut(msg);

        }
        if(msg.order == 3){
            let ClientProof = Buffer.from(msg.ClientProof, 'base64').toString();
            let proof = ClientProof;
            let iteration = msg.iteration;
            let commonNonce = Buffer.from(msg.r, 'base64').toString();
            let testProof = salting(password, commonNonce, iteration);
            
            console.log('Client SHA256 password (server side): ' + testProof);
            console.log('Client SHA256 password (client side): ' + proof);    
            
            setTimeout(() => {
            if(testProof == proof){
                msg.status = 'success';
                let commonNonce = Buffer.from(msg.r, 'base64').toString();
                let iteration = msg.iteration;
                let serverProofPure = salting(serverPassword, commonNonce, iteration);
                let serverProof = Buffer.from(serverProofPure).toString('base64');
                msg.ServerProof = serverProof;
                console.log('Authentication successful!!!')
                setTimeout(() => {
                console.log('Encoded ServerProof: '+ serverProof);
                console.log('ServerProof: '+ serverProofPure);
            }, 1500);
            }else{
                msg.status = 'fail';
                console.log('Authentication of client failed!!!')
            }
            msg.order = 4;
            dataTimeOut(msg);
            }, 3500);
        }

        
    })

    
})

server.listen(1337, '127.0.0.1');
