# The Ref

The Ref is a sports debate web app where users can debate controversial sports plays, vote on calls, and discuss them through comments and replies. The goal of the app is to give sports fans a place to argue both sides of a play and settle the call through community voting.

## Features

- User registration and login
- JWT-based authentication
- Role-based permissions for users, moderators, and admins
- Admin/moderator-only post creation
- Sports posts with title, sport, description, video link, and thumbnail
- Voting system with one vote per user
- Vote percentages and total voters displayed
- Comment system with replies
- Edit and delete comment functionality
- Users can only delete their own comments unless they are an admin
- Comment likes with one like per user
- Sport filtering for Football, Basketball, Baseball, Soccer, and All
- Dark-themed frontend layout

## Tech Stack

### Frontend

- React
- Vite
- CSS

### Backend

- Node.js
- Express
- PostgreSQL
- Supabase
- JWT authentication
- bcrypt

## Project Structure

```text
project/
├── client/        # React frontend
├── server/        # Express backend
└── README.md
```

## How to Run the Project

To run this project, you need to start the backend server and the frontend app in two separate terminals.

### Terminal 1: Run the Backend

From the main project folder, run:

```bash
cd server
npm install
npm run dev
```

The backend will run at:

```text
http://localhost:8080
```

### Terminal 2: Run the Frontend

Open a second terminal. From the main project folder, run:

```bash
cd client
npm install
npm run dev
```

The frontend will run at:

```text
http://localhost:5173
```

Open this link in your browser:

```text
http://localhost:5173
```

## Environment Variables

Before running the backend, create a `.env` file inside the `server` folder.

Example `.env` file:

```env
PORT=8080
CLIENT_ORIGIN=http://localhost:5173
DATABASE_URL=your_supabase_database_url
JWT_ACCESS_SECRET=your_access_secret
JWT_REFRESH_SECRET=your_refresh_secret
ACCESS_TOKEN_TTL_MIN=15
REFRESH_TOKEN_TTL_DAYS=7
```

The `.env` file is not pushed to GitHub because it contains private information.

## Database

This project uses PostgreSQL through Supabase.

Main tables include:

- `users`
- `refresh_tokens`
- `posts`
- `comments`
- `votes`
- `comment_likes`


## Roles and Permissions

| Role | Permissions |
|---|---|
| User | View posts, vote, comment, reply, like comments, and edit/delete their own comments |
| Moderator | User permissions plus ability to add posts |
| Admin | Full access, including deleting any comment |

## Purpose

This project was built for a compiter science course to practice full-stack development, authentication, database design, role-based access control, and user interaction features.

## Future Improvements

- Add user profile pages
- Make Search Functionality better
- Make mobile
- Add better video preview handling
- Add reporting/moderation tools
- Add more sports categories
- Deploy frontend and backend publicly

## Author

Anwaar Khan
