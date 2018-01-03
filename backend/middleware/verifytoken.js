var jwt = require('jsonwebtoken');
var con = require('../db');

var  verifytoken= function(req,res,next) {
  var token = req.body.token || req.query.token || req.headers['x-access-token'] || req.headers['authorization'];
	
	if (token) {
	token=token.replace("Bearer","");
	token=token.trim();
	console.log("here",token);
        jwt.verify(token,'RESTFULAPIs', function(err, decoded) {
            if (err) { 
                return res.json({"error": err});
            }
            req.decoded = decoded;
            con.query("select * from expired_data WHERE tvalue =?",token,(err, result) => {
                if (err) {
                  res.send({ error: err.message });
                } else {
                   if(result.length == 0) 
                   {
                    next(); 
                   } else{
                    return res.status(403).send({"error": "Please login and continue..."});
                   }
                }
              });
        });
    } else {
        return res.status(403).send({"error": "Token not received"});
    }
}

module.exports = verifytoken;