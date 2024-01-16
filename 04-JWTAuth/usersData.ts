interface User {
  username: string;
  password: string;
  refreshToken?: string;
}

const users: User[] = [];

export default users;
