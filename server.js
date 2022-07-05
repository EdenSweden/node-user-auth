const express = require('express');
const app = express();
//bcrypt library is async & returns promises.
const bcrypt = require('bcrypt');

//allows our app to accept json
app.use(express.json())

//In a real-world app, we'd use a DB. Users array is for testing.
const users = [];

app.get('/users', (req, res) => {
    res.json(users);
})

app.post('/users', async (req, res)=> {
    try {
        //a unique salt is added to each hashed pw so users with same pw can't all be hacked by someone malicious.
        //optional number passed as parameter below is more secure the greater it is, but takes longer to generate.
        //const salt = await bcrypt.genSalt();
        //but instead of above line, you can pass the number of rounds you want into hash fn below. (here, 10)
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        
        //bcrypt automatically stores salt w/ hashed password.
        const user = { name: req.body.name, password: hashedPassword };
        users.push(user);
        res.status(201).send();
    } catch {
        res.status(500).send();
    }
    
})

app.post('/users/login', async (req, res) => {
    const user = users.find(user => user.name = req.body.name);
    if(user == null){
        return res.status(400).send('Cannot find user.');
    }
    try {
        //user.password is the hashed version stored in db (or user array here)
        //bcrypt.compare is ideal way to do this b/c it protects from timing attacks.
        if(await bcrypt.compare(req.body.password, user.password)){
            res.send('Success!');
        } else {
            res.send('Not allowed.');
        }
    } catch {
        res.status(500).send();
    }
})

app.listen(3000, () => console.log('Server started.'))