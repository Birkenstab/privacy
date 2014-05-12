var sqlite3 = require("sqlite3");
var express = require("express");
var app = express();
var scrypt = require("scrypt");
var async = require("async");
var crypto = require('crypto');
var actions = require("actions");

var __SessionExpire = 86400000; //ms
var __StandardUserGroup = 1001;

var TheActions = {
	login:Login,
	getdata:DoGetData
};

var UserDB = new sqlite3.Database("Users.db3");
var SessionDB = new sqlite3.Database("Sessions.db3");

function init()
{
	CreateTables();
	//app.use(express.compress());
	
	app.post('/Action', function(req, res)
	{
		var body = '';
        req.on('data', function (data)
        {
            body += data;
            // 1e6 === 1 * Math.pow(10, 6) === 1 * 1000000 ~~~ 1MB
            if (body.length > 1e6) { 
                // FLOOD ATTACK OR FAULTY CLIENT, NUKE REQUEST
                req.connection.destroy();
            }
        });
        req.on('end', function ()
        {
        	var data = JSON.parse(body);
        	GetUserInfos(data.sessionid,function(err,Infos)
        	{
        		delete data.sessionid;
        		if (err)
        			console.error("app.post('Action') error: " + err);
        		
	        	actions.split(data, TheActions, function(Data)
	        	{
		        	res.status = 200;
					res.type("application/json");
					res.send(Data);
	        	},{req:req,UserInfos:Infos});
        	});
        });
	});
	app.listen(8080);
}

function GetUserInfos(SessionID,Callback)
{
	SessionDB.all("SELECT UserID FROM Sessions WHERE SessionID = ? AND Expire > ?;",SessionID,new Date().getTime(),function(err, rows)
	{
		if (!err)
		{
			if (rows.length == 1)
			{
				var UserID = rows[0].UserID;
				console.log("UserID ist " + UserID);
			}
			else
			{
				var UserID = 0;
				console.log("GetUserInfos: SessionID '" + SessionID + "' does not exist or has expired");
			}
			
			GetUserInfosByUserID(UserID,function(err2,Infos)
			{
				if (!err2)
				{
					console.log(JSON.stringify(Infos));
					Callback(null,Infos);
				}
				else
				{
					Callback("GetUserInfos Error: " + err2,null);
				}
			});
		}
		else
		{
			Callback("GetUserInfos Error: " + err.message,null);
		}
	});
}

function GetUserInfosByUserID(UserID,Callback)
{
	if (UserID != 0)
	{
		UserDB.all("SELECT Username,UserGroup,Mail,UserID FROM Users WHERE UserID = ?;",UserID,function(err, rows)
		{
			if (!err)
			{
				if (rows.length == 1)
				{
					Callback(null,{
						UserID:rows[0].UserID,
						Username:rows[0].Username,
						UserGroup:rows[0].UserGroup,
						Mail:rows[0].Mail
					});
				}
				else
				{
					Callback("GetUserInfosByUserID Error: User does not exist",null);
				}
			}
			else
			{
				Callback("GetUserInfosByUserID Error: " + err.message,null);
			}
		});
	}
	else
	{
		Callback(null,{
			UserID:0,
			Username:"",
			UserGroup:0,
			Mail:""
		});
	}
}

function CreateTables()
{
	//UserDB.serialize();
	UserDB.run("CREATE TABLE IF NOT EXISTS Users (UserID INTEGER PRIMARY KEY AUTOINCREMENT,Username TEXT NOT NULL,Password TEXT NOT NULL,Mail TEXT NOT NULL,UserGroup INTEGER NOT NULL,MailBestaetigt INT2,Gesperrt INT2,Registriert TEXT);");
	SessionDB.run("CREATE TABLE IF NOT EXISTS Sessions (SessionID TEXT NOT NULL, Expire TEXT NOT NULL, Created TEXT NOT NULL, UserID INTEGER NOT NULL);")
}

function Login(Data,Callback,Infos)
{
	switch(Data.action)
	{
		case("login"):
			DoLogin(Data,Callback);
			break;
		case("register"):
			DoRegister(Data,Callback);
			break;
		default:
			return {userid:Infos.UserInfos.UserID,
	    			username:Infos.UserInfos.Username,
	    			usergroup:Infos.UserInfos.UserGroup};
			break;
	}
}

function CreateID(Length)
{
	return crypto.randomBytes(Length).toString("base64");
}

function CreateIDAndCheck(Length,DB,Table,Field,Callback,Timeout)
{
	if (Timeout == 0)
	{
		Callback(null,"Timeout while creating ID");
	}
	
	if (!Timeout) Timeout = 50;
	
	if (!Field) Field = "ID";
	var ID = CreateID(Length);
	DB.all("SELECT ? FROM '" + Table + "' WHERE ? = ?;",[
		Field,
		Field,
		ID
	],function(err,rows)
	{
		if (!err)
		{
			if (rows.length == 0)
			{
				Callback(ID,null);
			}
			else
			{
				CreateIDAndCheck(Length,DB,Table,Field,Callback,Timeout-1);
			}
		}
		else
		{
			Callback(null,"CreateIDAndCheck: Error while checking ID: " + err.message);
		}
	});
}

function DoLogin(Data,Callback)
{
	var Zeit = new Date().getTime();
	console.log("Ich fang jetzt an");
	
	console.log("Benutzer: " + Data.user);
	console.log("Passwort: " + Data.password);
	console.log("Anmeldung erfolgt…");
	
	UserDB.all("SELECT Password,UserID,Username,UserGroup FROM Users WHERE Username = ?;",Data.user,function(err, rows)
	{
		if (!err)
		{
			if (rows.length == 1)
			{
				scrypt.verify.config.keyEncoding = "utf8";
				scrypt.verify.config.hashEncoding = "base64";
				scrypt.verify(rows[0].Password, Data.password, function(err, result) {
				    if (result == true)
				    {
					    CreateIDAndCheck(30,SessionDB,"Sessions","SessionID",function(ID,err25)
					    {	
					    	if (!err25)
					    	{
						    	SessionDB.run("INSERT INTO Sessions (SessionID,Expire,Created,UserID) VALUES ($SessionID,$Expire,$Created,$UserID);",{
							    	$SessionID:ID,
							    	$Expire: new Date().getTime() + __SessionExpire,
							    	$Created: new Date().getTime(),
							    	$UserID: rows[0].UserID
						    	},function(err2)
						    	{
						    		if (!err2)
						    		{
						    			Callback({
							    			success:true,
							    			sessionid:ID,
							    			userid:rows[0].UserID,
							    			username:rows[0].Username,
							    			usergroup:rows[0].UserGroup
						    			});
										console.log("DoLogin: User " + Data.user + " logged in successfully");
										console.log("Zeit: " + (new Date().getTime() - Zeit));
									}
									else
									{
										console.error("DoLogin: Error while creating Session: " + err2.message);
										Callback({success:false});
									}
						    	});
						    }
						    else
						    {
							    console.log("DoLogin: ID creation and checking failed: " + err25);
							    Callback({success:false});
						    }
					    });
				    }
				    else
				    {
				    	console.log("DoLogin: Wrong password for User " + Data.user + " (" + rows[0].UserID + ")");
					    Callback({success:false,showmsg:"login.wrongpassword"});
				    }
				});
			}
			else
			{
				console.log("Wrong password for User " + Data.user);
				Callback({success:false,showmsg:"login.wrongpassword"});
			}
		}
		else
		{
			console.error("DoLogin: Error while loggin in User " + Data.user + ": " + err.message);
			Callback({success:false});
		}
	});
}

function DoRegister(Data,Callback)
{
	var Zeit = new Date().getTime();
	console.log("Ich fang jetzt an");
	
	var Mail = Data.mail;
    var User = Data.user;
    var Password;
    var UserGroup = __StandardUserGroup;
    var MailBestaetigt = false;
    var Gesperrt = false;
    var Registriert = new Date().getTime();

	scrypt.hash.config.keyEncoding = "utf8";
	scrypt.hash.config.outputEncoding = "base64";
	scrypt.hash(Data.password, {N: 18, r:8, p:1}, function(err, result){
		if (!err)
		{
		    console.log("Asynchronous result: "+result);
		    console.log("Zeit: " + (new Date().getTime() - Zeit));
		    Password = result;
		    UserDB.run("INSERT INTO Users (Username, Password,Mail,UserGroup,MailBestaetigt,Gesperrt,Registriert) VALUES ($Username,$Password,$Mail,$UserGroup,$MailBestaetigt,$Gesperrt,$Registriert)",{
			    $Username:User,
			    $Password:Password,
			    $Mail:Mail,
			    $UserGroup:UserGroup,
			    $MailBestaetigt: Number(MailBestaetigt),
			    $Gesperrt: Number(Gesperrt),
			    $Registriert:Registriert
		    },function(error)
		    {
		    	if (!error)
		    	{
		    		console.log("User " + User + " wurde erfolgreich erstellt");
			    	Callback({success:true});
			    }
			    else
			    {
			    	console.error("DoRegister: User creation failed: " + error.message);
				    Callback({success:false});
			    }
		    });
		 }
		 else
		 {
		 	console.error("DoRegister: Hash creation failed: " + JSON.stringify(err));
			Callback({success:false});
		 }
	});
}

function add(Name,Methode)
{
	if (typeof Name === "object" && Data === undefined && Callback === undefined)
	{
		Name = Name.Name;
		Methode = Name.Methode;
	}
	
	if (TheActions["hasOwnProperty"](Name) === false)
	{
		TheActions[Name] = Methode;
	}
	else
	{
		throw new Error("The function '" + Name + "' already exists");
	}
}

function DoGetData(Data,Callback,Infos)
{
	if (Infos.UserInfos)
	{
		var UserID = Infos.UserInfos.UserID;
		var Benutzername = Infos.UserInfos.Username;
	}
	return {Benutzername:Benutzername,asd:Data,ID:UserID};
}


module.exports = {
	init:init,
	add:add
};