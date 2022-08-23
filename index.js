//import express
const express = require('express')
const router = express.Router()														//import express router
const bcrypt = require("bcrypt");													//import bcrypt
require('dotenv').config()																//IMPORT .ENV

//import firebase utilities
const { initializeApp, applicationDefault, cert } = require('firebase-admin/app');
const { getFirestore, Timestamp, FieldValue } = require('firebase-admin/firestore');

//import service account key
const serviceAccount = require('/serviceAccountKey.json');

//verify service account key
initializeApp({
  credential: cert(serviceAccount)
});

const db = getFirestore();


//On get request render the signup form
router.get('/signup', function(req, res, next) {
  res.render('signup');
});


//On post request: verify and add data to database, Also send verification email.
router.post('/signup', function(req, res, next) {
	//import valiables
	let email = req.body.email;
	let name = req.body.name;
	let password = req.body.password;

	//validate form data
	req.checkBody('email', 'Oops! A valid email is required. 😅').isEmail()	//validate email

	var errors = req.validationErrors()

	//If no errors are found continue registration
	if( !errors ) {
//Look for already registered email
		async function findemail() {
			const cityRef = db.collection('users').doc(email);
			const doc = await cityRef.get();
			if (!doc.exists) {

  			//if Email not found proceed with adding data:
      	var user_name = req.sanitize('name').escape().trim();
				var user_email = req.sanitize('email').escape().trim();
				var user_password = req.sanitize('password').escape().trim();

				//encrypt password
				const salt = await bcrypt.genSalt(10);
				user_password = await bcrypt.hash(user_password, salt);

				//add data to cloud firebase. Using add user function
				async function adduser() {
  				const docRef = db.collection('users').doc(user_email);
  				await docRef.set({
      			name: user_name,
      			email: user_email,
      			password: user_password,
  				});
				}

				adduser();		//recall the function
				res.end();
			} else {
					//send user back to signup if email already exists
					var error_msg = 'Email aready exists. Looks like you have a twin.😁';
					req.flash('error', error_msg)
					res.render('signup', { 
						title: 'Registration Page',
						name: req.body.name,
						email: req.body.email,
						password: ''
					})
				}
		}
		findemail();
	}
	//DISPLAY ERRORS TO USER
	else {
		var error_msg = ''
		errors.forEach(function(error) {
			error_msg += error.msg + '<br>'
		})                
		req.flash('error', error_msg)
		res.render('signup', { 
			title: 'Registration Page',
			name: req.body.name,
			email: req.body.email,
			password: ''
		})
	}
})

//export router function
module.exports = router;