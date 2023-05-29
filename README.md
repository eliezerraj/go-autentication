# go-autentication

DROP TABLE public."user_authentication";

CREATE TABLE public."user_authentication" (
	id 				serial4 NOT NULL,
	user_id 		varchar(100) NULL,
	kid 		    varchar(100) NULL,
	status 			varchar null,
	created_date 	timestamp
);

