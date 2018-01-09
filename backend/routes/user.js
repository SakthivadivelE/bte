var express = require('express');
var router = express.Router();
var con = require('../db');
var bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');
var verifytoken = require('../middleware/verifytoken');
var _=require('underscore');

const saltRounds = 10;




router.get('/', (req, res) => {
  res.send("Welcome");
});

router.post('/userRegistration', (req, res) => {

  var userdata=req.query.data || req.body.data;
  userdata = JSON.parse(userdata);
  
  var isAdmin = userdata.isAdmin !== undefined ? userdata.isAdmin :0;

  var password = '';
  bcrypt.hash(userdata.password, saltRounds, (err, hash) => {
    password = hash;
    var data = {
      username: `${userdata.firstname}${userdata.lastname}`,
      isAdmin: isAdmin,
      email: `${userdata.email}@knowledgeq.com`,
      empID: userdata.empID,
      password: password,
      date: new Date(new Date().toUTCString()),
      notify: userdata.notify,
      interest: userdata.interest
    }

    con.query("insert into users SET ?", data, (err, result) => {
      if (err) {
        res.status(500).send(err.message);
      } else {
        res.status(200).json({message:'User registered successfully..'});
      }
    });
  });
});

router.get('/editProfile', verifytoken,(req, res) => {

  var userdata=req.query.data || req.body.data;
  userdata = JSON.parse(userdata);
  
  var isAdmin = userdata.isAdmin !== undefined ? userdata.isAdmin :0;
  var user_id = userdata.user_id;

 
    var data = {
      username: `${userdata.username}`,
      isAdmin: isAdmin,
      email: `${userdata.email}@knowledgeq.com`,
      empID: userdata.empID,
      date: new Date(new Date().toUTCString()),
      notify: userdata.notify,
      interest: userdata.interest
    }

    con.query("UPDATE users SET ? where user_id = ?", [data,user_id], (err, result) => {
      if (err) {
        res.status(500).send(err.message);
      } else {
        res.status(200).json({message:'Profile updated successfully..'});
      }
    });
 
});

router.post('/login', (req, res) => {
  var data=req.query.data || req.body.data;
  data = JSON.parse(data);

  var userData= {
    username:data.username,
    password:data.password
  }

  con.query(`select * from users where username = ?`, userData.username, (err, user) => {
    if (err) {
      res.json({ error: err.message });
    } else {
      if (user.length > 0) {
        bcrypt.compare(userData.password, user[0].password,(err, result) => {
          if (err) throw err;
          if (!result) {
            res.json({ error: 'Wrong username or password' });
          } else {
            var logouttime;
            if(user[0].last_login < user[0].last_logout_time) {
              logouttime = user[0].last_logout_time;
            } else {
              logouttime = user[0].token_expire;
            }
            var date=new Date(new Date().toUTCString());
            var tokenExpiry=new Date(new Date().toUTCString());
            tokenExpiry.setHours(tokenExpiry.getHours()+1);
            con.query("update users SET last_login = ? , last_logout_time = ? ,token_expire = ? where user_id=?",[date,logouttime,tokenExpiry,user[0].user_id], (err, result) => {
              if (err) {
                res.json({ error: err.message });
              } else {
                res.json({ error:null,token: jwt.sign({ email: user[0].email, username: user[0].username, id: user[0].id }, 'RESTFULAPIs', { expiresIn: '1h' }),user });
              }
            });
          }
        });
      } else {
        res.json({error:'Wrong username or password'});
      }
    }
  });
});


router.get('/changePassword', verifytoken, (req, res) => {
  var token = req.body.token || req.query.token || req.headers['x-access-token'] || req.headers['authorization'];
  var data=req.query.data;
  data = JSON.parse(data);
  var userData = {
    username:data.username,
    old_password:data.old_password,
    new_password:data.new_password,
	confirm_password:data.confirm_password
  }
  
    token=token.replace("Bearer","");
	token=token.trim();
	console.log("@@@@@@@@@@",token);
  
  if(userData.confirm_password == userData.new_password) {
 
  con.query(`select * from users where username = ?`, userData.username, (err, user) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      if (user.length > 0) {
        bcrypt.compare(userData.old_password, user[0].password, (err, result)=> {
          if (err) throw err;
          if (!result) {
            res.status(200).send({ message: 'Wrong old password' });
          } else {
            var password = '';
            bcrypt.hash(userData.new_password, saltRounds, (err, hash) => {
              password = hash;
              con.query("update users SET password = ?", password , (err, result) => {
                if (err) {
                  res.send({ error: err.message,message:"Password changing failed.." });
                } else {

                  var logouttime;
                  if(user[0].last_login < user[0].last_logout_time) {
                    logouttime = user[0].last_logout_time;
                  } else {
                    logouttime = user[0].token_expire;
                  }

                  var date=new Date(new Date().toUTCString());
                  var tokenExpiry=new Date(new Date().toUTCString());
                  tokenExpiry.setHours(tokenExpiry.getHours()+1);

                  con.query("update users SET last_login = ? , last_logout_time = ?, token_expire = ? ",[date,logouttime,tokenExpiry], (err, result) => {
                    if (err) {
                      res.send({ error: err.message });
                    } else { 
                      var data={
                        tvalue:token,
                        date_added:new Date(new Date().toUTCString())
                     }
                     con.query("insert into expired_data SET ?", data, (err, result) => {
                       if (err) {
                         res.status(500).send({ error: err.message });
                       } else {
                        res.status(200).send({ message:'success',token: jwt.sign({ email: user[0].email, username: user[0].username, id: user[0].id }, 'RESTFULAPIs', { expiresIn: '1h' }),user });
                       }
                     });

                    }
                  });
                }
              });
            });
          }
        });
      } else {
        res.status(200).send({message:'User not found'});
      }
    }
  });
  
  } else {
	  res.status(200).send({message:"New password not match confirm password"});
  }

});


router.get('/logout', verifytoken,(req, res) => {
	
	 var data=req.query.data;
  data=JSON.parse(data);
  
  var user_id = parseInt(data.user_id);
 
	
  var token = req.body.token || req.query.token || req.headers['x-access-token'] || req.headers['authorization'];
	
  if (token) {
	  
	  token=token.replace("Bearer","");
	token=token.trim();
	console.log("@@@@@@@@@@",token);
	
    var data={
       tvalue:token,
       date_added:new Date(new Date().toUTCString())
    }

    con.query("insert into expired_data SET ?", data, (err, result) => {
      if (err) {
        res.send({ error: err.message });
      } else {
        var date=new Date(new Date().toUTCString());
        con.query("update users SET last_logout_time = ? where user_id = ?",[date,user_id], (err, result) => {
          if (err) {
            res.status(500).send({ error: err.message , status:500});
          } else {
            res.status(200).send({message:'Logout success...', status:200});
          }
        });
      }
    });
  } else {
      return res.status(403).send({"error": "Token not received"});
  }
});

router.get('/addTopics', verifytoken, (req, res) => {
  var data=req.query.data;
  data=JSON.parse(data);
  var data = {
    title: data.title,
    total_posts:0,
    date: new Date(new Date().toUTCString())
  }
  con.query("insert into topics SET ?", data, (err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send('Topic added successfully...');
    }
  });
});

router.get('/createPost', verifytoken, (req, res) => {
  var data=req.query.data;
  data = JSON.parse(data);

  var data = {
    title: data.title,
    description: data.description,
    user_id:data.user_id,
    topic_id:data.topic_id,
    created_date: new Date(new Date().toUTCString()),
    solution: data.solution,
    isApproved:0,
    isRejected:0,
    rejectReason:null
  }
  con.query("insert into posts SET ?", data, (err, result) => {
    if (err) {
      res.status(500).send({ error: err.message });
    } else {
      res.status(200).send('Post added successfully and waiting for admin approvals...');
    }
  });
});

router.get('/approvePost', verifytoken, (req, res) => {
  var data=req.query.data;
  data = JSON.parse(data);

  var data = {
    post_id:data.post_id,
    topic_id:data.topic_id
  }
  
  con.query("update posts SET isApproved = 1 WHERE post_id = ?", data.post_id, (err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      con.query("update topics SET total_posts = total_posts+1 WHERE topic_id = ?", data.topic_id, (err, result) => {
        if (err) {
          res.status(500).send({ error: err.message,this:"this" });
        } else {
          res.status(200).send({message : 'Post approved successfully..'});
        }
      });
    }
  });
});

router.get('/rejectPost', verifytoken, (req, res) => {
  var data=req.query.data;
  data = JSON.parse(data);
  var data = {
    post_id:data.post_id,
    rejectReason:data.reason
  }
  con.query("update posts SET isRejected = 1,isApproved = 0, rejectReason = ? WHERE post_id = ?", [data.rejectReason, data.post_id], (err, result) => {
    if (err) {
      res.status(500).send({ error: err.message });
    } else {
      res.status(200).send({message : 'Post rejected...'});
    }
  });
});

router.get('/deletePost', verifytoken, (req, res) => {
  var data=req.query.data;
  data = JSON.parse(data);
  var data = {
    post_id:data.post_id,
  }
  con.query("delete from posts WHERE post_id = ?",data.post_id, (err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      con.query("delete from answers WHERE post_id = ?",data.post_id, (err, result) => {
        if (err) {
          res.status(500).send({ error: err.message });
        } else {
          res.status(200).send({message:'Post deleted...'});
        }
      });
    }
  });
});

router.get('/addAnswer', verifytoken, (req, res) => {
  var data=req.query.data;
  data = JSON.parse(data);

  var data = {
    user_id:parseInt(data.user_id),
    post_id:parseInt(data.post_id),
    description: data.description,
    rating:0,
    total_points:0,
    rated:0,
    date_answered: new Date(new Date().toUTCString())
  }
  
  
  
  con.query("insert into answers SET ?", data, (err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      con.query("update posts SET last_updated = ?, total_answers = total_answers + 1 WHERE post_id= ?", [data.date_answered,data.post_id], (err, result) => {
        if (err) {
          res.status(500).send({ error: err.message });
        } else {
          res.status(200).send({message:'Answer added to the post successfully...'});
        }
      }); 
    }
  });
});

router.get('/rateAnswer', verifytoken, (req, res) => {
  var data=req.query.data;
  data = JSON.parse(data);

  var data = {
    answer_id:data.answer_id,
    rating:data.rating
  }

  con.query("select total_points, rated  from answers WHERE answer_id = ?",data.answer_id, (err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
     var avgRating=(result[0].total_points + data.rating)/(result[0].rated+1);
      con.query("update answers SET rating = ?, total_points= ?, rated = ? WHERE answer_id = ?",[avgRating,result[0].total_points+data.rating,result[0].rated+1,data.answer_id], (err, result) => {
        if (err) {
          res.send({ error: err.message });
        } else {
          res.send('Answer rated successfully...');
        }
      });
    }
  });
});

router.get('/listTopics',(req, res) => {
  con.query("select topic_id,title,total_posts from topics",(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send(result);
    }
  });
});

router.get('/listUserAskedPosts', verifytoken, (req, res) => {
  var data=req.query.data;
  data = JSON.parse(data);

  var userdata = {
    user_id:data.user_id,
    start:data.start,
    limit:data.limit
  }

  con.query("select * from posts WHERE user_id = ? limit ?,?",[userdata.user_id,data.start,data.limit],(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send(result);
    }
  });
});

router.get('/listUserAnsweredPosts', verifytoken, (req, res) => {
  var data=req.query.data;
  data = JSON.parse(data);

  var userdata = {
    user_id:data.user_id,
    start:data.start,
    limit:data.limit
  }

  con.query("SELECT posts.post_id, posts.title, posts.description, posts.total_answers, posts.last_updated FROM posts INNER JOIN answers ON posts.post_id = answers.post_id WHERE answers.user_id =? LIMIT ? , ?",[userdata.user_id,data.start,data.limit],(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send(result);
    }
  });
});

router.get('/listUserPosts', verifytoken, (req, res) => {
  var data=req.query.data;
  data = JSON.parse(data);

  var userdata = {
    user_id:data.user_id,
    start:data.start,
    limit:data.limit
  }

  con.query("SELECT posts.post_id, posts.title, posts.description, posts.total_answers,posts.last_updated FROM posts INNER JOIN answers ON posts.post_id = answers.post_id WHERE answers.user_id =? or posts.user_id =? LIMIT ? , ?",[userdata.user_id,userdata.user_id,data.start,data.limit],(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send(result);
    }
  });
});


router.get('/listLatestTopicPosts', verifytoken, (req, res) => {
	
  var data=req.query.data;
  data = JSON.parse(data);

  var userdata = {
    topic_id:data.topic_id,
    start:data.start,
    limit:data.limit
  }

  con.query("select * from posts WHERE isApproved=1 AND topic_id = ? ORDER BY created_date desc limit ?,?",[userdata.topic_id,data.start,data.limit],(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send(result);
    }
  });
});

router.get('/listLatestTopicPostsForUser', verifytoken, (req, res) => {
  var data=req.query.data;
  data = JSON.parse(data);

  var userdata = {
    user_id:data.user_id,
    topic_id:data.topic_id,
    start:data.start,
    limit:data.limit
  }
  
  console.log(userdata);

  con.query("select last_logout_time, last_login ,token_expire from users WHERE  user_id= ?",userdata.user_id,(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      var logouttime = result[0].last_logout_time;
      var logintime = result[0].last_login;
      con.query("select * from posts WHERE isApproved=1 AND topic_id = ? AND created_date > ? And created_date < ? ORDER BY created_date desc limit ?,?",[userdata.topic_id,logouttime,logintime,data.start,data.limit],(err, result) => {
        if (err) {
          res.send({ error: err.message });
        } else {
          res.send(result);
        }
      });
    }
  });
});

router.get('/listMostAnsweredTopicPosts', verifytoken, (req, res) => {
  var data=req.query.data;
  data = JSON.parse(data);

  var userdata = {
    topic_id:data.topic_id,
    start:data.start,
    limit:data.limit
  }

  con.query("select * from posts WHERE isApproved=1 AND topic_id = ? ORDER BY total_answers desc limit ?,?",[userdata.topic_id,data.start,data.limit],(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send(result);
    }
  });
});


router.get('/listLatestApprovedPosts', verifytoken, (req, res) => {

  var data=req.query.data;
  data=JSON.parse(data);

  con.query("select * from posts WHERE isApproved = 1 ORDER BY created_date desc limit ?,?",[data.start,data.limit],(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send(result);
    }
  });
});

router.get('/countApprovedPosts', verifytoken, (req, res) => {
  con.query("select COUNT(*) As postCount from posts WHERE isApproved = 1 ",(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send({count:result[0].postCount});
    }
  });
});

router.get('/countRejectedPosts', verifytoken, (req, res) => {
  con.query("select COUNT(*) As postCount from posts WHERE isRejected = 1 ",(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send({count:result[0].postCount});
    }
  });
});

router.get('/listMostAnsweredApprovedPosts', verifytoken, (req, res) => {
 
  var data=req.query.data;
  data=JSON.parse(data);

  con.query("select * from posts WHERE isApproved = 1 ORDER BY total_answers desc limit ?,?",[data.start,data.limit],(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send(result);
    }
  });
});

router.get('/listRejectedPosts', verifytoken, (req, res) => {
	
  var data=req.query.data;
  data=JSON.parse(data);
  
  con.query("select * from posts WHERE isRejected = 1 limit ?,?",[data.start,data.limit],(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send(result);
    }
  });
});

router.get('/postsWaitingForApprovals', verifytoken, (req, res) => {
	
	var data=req.query.data;
  data=JSON.parse(data);
  
  con.query("select * from posts WHERE isRejected = 0 AND isApproved=0 limit ?,?",[data.start,data.limit],(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send(result);
    }
  });
});

router.get('/getPostAnswers', verifytoken, (req, res) => {
  var data=req.query.data;
  data = JSON.parse(data);

  var userdata = {
    post_id:data.post_id
  }

  con.query("select * from answers WHERE post_id = ?",userdata.post_id,(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send(result);
    }
  });
});

router.get('/searchPosts', verifytoken, (req, res) => {
  var data=req.query.data;
  data = JSON.parse(data);

  var userdata = {
    keywords:data.keywords
  }

var searchString='';
  _.each(userdata.keywords, (e,index)=> {
    searchString+=e;
    if(index !== userdata.keywords.length-1)
    searchString+='|';
  });

  con.query("SELECT DISTINCT posts.post_id, posts.title, posts.description, posts.total_answers FROM posts INNER JOIN answers ON posts.post_id = answers.post_id WHERE answers.description REGEXP  ? UNION SELECT posts.post_id, posts.title, posts.description, posts.total_answers  FROM posts WHERE posts.title REGEXP  ? OR posts.description REGEXP  ? OR posts.solution REGEXP  ? LIMIT 0 , 30",[searchString,searchString,searchString,searchString],(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send(result);
    }
  });
});

router.get('/listUsers', verifytoken, (req, res) => {
  con.query("select user_id,username from users",(err, result) => {
    if (err) {
      res.status(500).send({ error: err.message });
    } else {
      res.status(200).send(result);
    }
  });
});

router.get('/searchUsers', verifytoken, (req, res) => {
  var data=req.query.data;
  data=JSON.parse(data);

  con.query("select user_id,username from users WHERE username like ?",'%'+data.name+'%',(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      res.send(result);
    }
  });
});

router.get('/removeUser', verifytoken, (req, res) => {
  var userdata=req.query.data;
  userdata=JSON.parse(userdata);

  var data={
    user_id:userdata.user_id
  }

  con.query("delete from users WHERE user_id = ?",data.user_id,(err, result) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      con.query("delete from posts WHERE user_id = ?",data.user_id,(err, result) => {
        if (err) {
          res.send({ error: err.message });
        } else {
          con.query("delete from answers WHERE user_id = ?",data.user_id,(err, result) => {
            if (err) {
              res.status(500).send({ error: err.message });
            } else {
              res.status(200).send({message:"User removed successfully..."});
            }
          });
        }
      });
    }
  });
});

router.get('/forgotPassword', (req, res) => {
  
  var data=req.query.data;
  data = JSON.parse(data);
  
  var userData = {
    username:data.username
  }
  
  con.query(`select * from users where username = ?`, userData.username, (err, user) => {
    if (err) {
      res.send({ error: err.message });
    } else {
      if (user.length > 0) {
            var password = '';
            bcrypt.hash(userData.new_password, saltRounds, (err, hash) => {
              password = hash;
              con.query("update users SET password = ?", password , (err, result) => {
                if (err) {
                  res.send({ error: err.message,message:"Password changing failed.." });
                } else {

                
                }
              });
            });
        
      } else {
        res.status(200).send({message:'User not found'});
      }
    }
  });
  
 

});

module.exports = router;
