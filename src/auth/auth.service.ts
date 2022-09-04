import { BadRequestException, Injectable } from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import { PrismaService } from '../prisma.service';
import { hash, verify } from 'argon2';
import { users } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
  ) {}

  async create(createAuthDto: CreateAuthDto) {
    const user = await this.prisma.prisma.users.create({
      data: {
        name: createAuthDto.name,
        password: await hash(createAuthDto.password),
      },
    });
    return this.setToken(user);
  }

  async login(loginDto: LoginDto) {
    const user = await this.prisma.prisma.users.findUnique({
      where: { name: loginDto.name },
    });
    if (user && (await verify(user.password, loginDto.password))) {
      return this.setToken(user);
    } else {
      throw new BadRequestException('密码错误');
    }
  }

  async setToken(user: users) {
    return {
      token: await this.jwt.signAsync({
        name: user.name,
        sub: user.id,
      }),
      user: user,
    };
  }

  async getAllUsers() {
    return this.prisma.prisma.users.findMany();
  }
}
