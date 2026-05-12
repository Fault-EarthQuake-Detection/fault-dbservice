# GeoValid - Database Service (fault-dbservice)

**GeoValid Database Service** is the robust backend API and database management service for the GeoValid fault and earthquake detection system. Built with Node.js and TypeScript, it utilizes Prisma ORM to ensure type-safe database access, streamlined migrations, and secure authentication flows.

## 🚀 Features

* **RESTful API Architecture:** Provides scalable endpoints for the GeoValid frontend and other microservices.
* **Database Management:** Uses **Prisma ORM** for structured, type-safe database queries and schema management.
* **Secure Authentication:** Built-in authentication middleware (`auth.ts`) to protect sensitive routes and user data.
* **Migration Tracking:** Automated database migrations ensure consistency across development and production environments.
* **TypeScript Integrated:** Fully typed codebase minimizing runtime errors and improving developer experience.

## 🛠️ Tech Stack

* **Runtime:** Node.js
* **Language:** TypeScript
* **ORM:** Prisma
* **API Framework:** Express.js (or similar lightweight Node framework)
* **Database:** Relational Database (e.g., PostgreSQL/MySQL) managed via Prisma

## 📂 Project Structure

* `src/`: Core application source code.
    * `index.ts`: Main entry point and server initialization.
    * `routes/`: API route definitions (e.g., `auth.ts`).
    * `middleware/`: Express middlewares, including authentication (`auth.ts`).
    * `utils/`: Reusable utilities like the Prisma client instance (`prisma.ts`).
* `prisma/`: Database configuration.
    * `schema.prisma`: The main Prisma schema defining data models.
    * `migrations/`: Version-controlled database migration history.
* `package.json` / `tsconfig.json`: Project dependencies and TypeScript configuration.

## ⚙️ Getting Started

### Prerequisites
* Node.js (v16+ recommended)
* npm, yarn, or pnpm
* A running relational database (e.g., PostgreSQL)

### Installation

1.  Clone the repository.
2.  Install dependencies:
    ```bash
    npm install
    ```
3.  Set up your environment variables. Create a `.env` file in the root directory and add your database URL:
    ```env
    DATABASE_URL="postgresql://user:password@localhost:5432/geovalid_db"
    ```
4.  Generate the Prisma Client:
    ```bash
    npx prisma generate
    ```
5.  Run database migrations to apply the schema:
    ```bash
    npx prisma migrate dev
    ```
6.  Start the development server:
    ```bash
    npm run dev
    ```

## 🧑‍💻 Developer

**Fikal Alif Al Amin**

## 📄 License

This project is open-source and available for development and learning purposes.
README.md
Menampilkan README.md.
