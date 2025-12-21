import 'dotenv/config';
import connectDB from './config/db.js';
import app from './src/app.js';

//create express app 




connectDB();

// Port number where app will run
const port = process.env.PORT || 4000;





//request will be passed in json for that we use below code
// App is configured in src/app.js

app.listen(port, '127.0.0.1', () => console.log(`Server started on Port: ${port}`));

process.on('unhandledRejection', (reason) => {
	console.error('Unhandled Rejection:', reason);
});
process.on('uncaughtException', (err) => {
	console.error('Uncaught Exception:', err);
});
