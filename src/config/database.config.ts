import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import * as dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config();

// Log the database connection settings (for debugging)
// console.log('Database connection settings:');
// console.log(`Host: ${process.env.DB_HOST || 'localhost'}`);
// console.log(
//   `Port: ${process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 5432}`,
// );
// console.log(`Username: ${process.env.DB_USERNAME || 'postgres'}`);
// console.log(`Database: ${process.env.DB_DATABASE || 'auth_api'}`);

export const databaseConfig: TypeOrmModuleOptions = {
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : 5432,
  username: process.env.DB_USERNAME || 'postgres',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE || 'nestjs-auth',
  entities: [__dirname + '/../**/*.entity{.ts,.js}'],
  synchronize: process.env.NODE_ENV !== 'production',
};
