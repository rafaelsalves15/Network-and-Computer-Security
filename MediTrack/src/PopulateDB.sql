USE MediTrack;

INSERT INTO users (username, password) VALUES ('new_user', 'new_password');
GRANT ALL PRIVILEGES ON MediTrack.* TO 'new_user'@'localhost' IDENTIFIED BY 'new_password';
FLUSH PRIVILEGES;
