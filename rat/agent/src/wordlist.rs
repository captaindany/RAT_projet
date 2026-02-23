/// SSH brute-force username list
pub static USERNAMES: &'static [&str] = &[
    "root",
    "admin",
    "ubuntu",
    "debian",
    "pi",
    "user",
    "vagrant",
    "ec2-user",
    "centos",
    "kali",
];

/// SSH brute-force password list (common defaults / weak credentials)
pub static PASSWORDS: &'static [&str] = &[
    "password",
    "admin",
    "root",
    "123456",
    "toor",
    "pa$$word",
    "pass",
    "raspberry",
    "vagrant",
    "changeme",
    "test",
    "letmein",
    "1234",
    "qwerty",
    "",          // empty password
    "admin123",
];
