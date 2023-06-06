# go-autentication

POC for autentication purposes

During /signIn the app try to get de KID via service getKID()

The getKID() try to retrieve de KID from POSTGRE IF the data not exists the service created a new KID (via UUID) and store it.

There is a Redis cache layer (repo) where the tokens KID revoked are stored.

This cache could be used for other purposes but for this POC it is enough

## Endpoints

GET /health

POST /revokeToken

	{
		"userKid": "559b05da-f048-4e4c-8071-ec284b11d6db"
	}

HMAC

POST /signIn

		{
			"userId": "eliezer100",
			"password": "abc123"
		}
	
POST /verify

	{
	"token": "eyJhbGciOiJIUzI1NiIsImtpZCI6IjU1OWIwNWRhLWYwNDgtNGU0Yy04MDcxLWVjMjg0YjExZDZkYiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImVsaWV6ZXI1Iiwic2NvcGUiOiJlc2NvcG8gMTIzIiwiaXNzIjoieHB0byBjb3Jwb3JhdGlvbiIsImV4cCI6MTY4NTM5ODAyNCwiaWF0IjoxNjg1Mzk0NDI0fQ.1wcw-Qx9FOtiT3a_hfjXRJpO6KCpXt6w1gn-v9NYDMY"
	}

POST /refreshToken

	{
	"token": "eyJhbGciOiJIUzI1NiIsImtpZCI6IjU1OWIwNWRhLWYwNDgtNGU0Yy04MDcxLWVjMjg0YjExZDZkYiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImVsaWV6ZXI1Iiwic2NvcGUiOiJlc2NvcG8gMTIzIiwiaXNzIjoieHB0byBjb3Jwb3JhdGlvbiIsImV4cCI6MTY4NTM5ODAyNCwiaWF0IjoxNjg1Mzk0NDI0fQ.1wcw-Qx9FOtiT3a_hfjXRJpO6KCpXt6w1gn-v9NYDMY"
	}

RSA

POST /signInRSA

	{
    	"userId": "eliezer100",
    	"password": "abc123"
	}

POST /verifyRSA

	{
	"token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImU1NmQyODBlLTEwZmItNDUxMy05YzYyLTI0YzYwODBhYzZlNSIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImVsaWV6ZXIiLCJzY29wZSI6ImVzY29wbyAxMjMiLCJpc3MiOiJ4cHRvIGNvcnBvcmF0aW9uIiwiZXhwIjoxNjg1NDcyNDYzLCJpYXQiOjE2ODU0Njg4NjN9.QgOQhdWBhV5CJxit43n7Q7IIhzxPL5M4EE0Sp3AOROngfOKTID4c8TfO2D2tb_Z2mVaXidrRaXyhkIE5SZRl6kbdw1i8LLeevrB1yGUyKe2QNCHskFY_Wa5OENT6xeumNBw7Gyl7qQPHcMTMl-9rAiHFBjW6G9LVffIbLf4cQHeAoKxnuKtIX--LsSNAvUOW90K5fD7oVecMWYbWBfP6Pt48NHQnbv02EMaOmJYnCVLSFE_f7OuwHeZmXAZCLyIE5xt7gY9fNWL_CCX8gmadnvOrsnqIgrj3YVYRoRRB7dCycDEpUdFgPZ2zZRNnTPLZ1X_4V2kPTGjZKtSs0-I7ZeTBRqt7r4tRpIAjzRD1_QB62Z-FwcUTVeO5Q5Q-TY3yk-StlI8Dbzzi7Tstf4VEKBKkrrl2Z5ZkNXxJ3Y6bE6oNa9D3C7EgxOg9OfsBRz0noe14AbqvxWBsHWDAqNhGRBxsugIc-LamnU2xreFfiRl3UbvTq6mvbUf6ScGttnGaNchieTN1vLoXNKaIyfizp7RTRiKOmw1V3E3TKuUHaICRN7hYhaGdkLP8BKVzrzwqGMEWvPzYCTHsBgA1ZNz5-9BWZ2jBm8mOX82C5Ji5oJhrS830HSWa4OWXSjtoc9cbBqAuoDW4_XBPXEfeZdnJmB-uFnvs1ql_RobfhEI8Mg8"
	}

POST /refreshRSAToken

	{
		"token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImU1NmQyODBlLTEwZmItNDUxMy05YzYyLTI0YzYwODBhYzZlNSIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImVsaWV6ZXIiLCJzY29wZSI6ImVzY29wbyAxMjMiLCJpc3MiOiJ4cHRvIGNvcnBvcmF0aW9uIiwiZXhwIjoxNjg1NDcyNDYzLCJpYXQiOjE2ODU0Njg4NjN9.QgOQhdWBhV5CJxit43n7Q7IIhzxPL5M4EE0Sp3AOROngfOKTID4c8TfO2D2tb_Z2mVaXidrRaXyhkIE5SZRl6kbdw1i8LLeevrB1yGUyKe2QNCHskFY_Wa5OENT6xeumNBw7Gyl7qQPHcMTMl-9rAiHFBjW6G9LVffIbLf4cQHeAoKxnuKtIX--LsSNAvUOW90K5fD7oVecMWYbWBfP6Pt48NHQnbv02EMaOmJYnCVLSFE_f7OuwHeZmXAZCLyIE5xt7gY9fNWL_CCX8gmadnvOrsnqIgrj3YVYRoRRB7dCycDEpUdFgPZ2zZRNnTPLZ1X_4V2kPTGjZKtSs0-I7ZeTBRqt7r4tRpIAjzRD1_QB62Z-FwcUTVeO5Q5Q-TY3yk-StlI8Dbzzi7Tstf4VEKBKkrrl2Z5ZkNXxJ3Y6bE6oNa9D3C7EgxOg9OfsBRz0noe14AbqvxWBsHWDAqNhGRBxsugIc-LamnU2xreFfiRl3UbvTq6mvbUf6ScGttnGaNchieTN1vLoXNKaIyfizp7RTRiKOmw1V3E3TKuUHaICRN7hYhaGdkLP8BKVzrzwqGMEWvPzYCTHsBgA1ZNz5-9BWZ2jBm8mOX82C5Ji5oJhrS830HSWa4OWXSjtoc9cbBqAuoDW4_XBPXEfeZdnJmB-uFnvs1ql_RobfhEI8Mg8"
	}


## Postgre

	CREATE TABLE public."user_authentication" (
		id 				serial4 NOT NULL,
		user_id 		varchar(100) NULL,
		kid 		    varchar(100) NULL,
		status 			varchar null,
		created_date 	timestamp
	);

