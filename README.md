# go-autentication

CREATE TABLE public."user_authentication" (
	id 				serial4 NOT NULL,
	user_id 		varchar(100) NULL,
	kid 		    varchar(100) NULL,
	status 			varchar null,
	created_date 	timestamp
);

select * from user_authentication;
delete from user_authentication;