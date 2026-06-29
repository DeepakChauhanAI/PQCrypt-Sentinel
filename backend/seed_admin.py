import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.models.models import Base, User
from app.auth.jwt import hash_password
from sqlalchemy.future import select


async def main():
    engine = create_async_engine(
        "postgresql+asyncpg://pqcrypt:pqcrypt@localhost:5432/pqcrypt"
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session() as s:
        res = await s.execute(select(User).where(User.email == "admin@pqc.local"))
        existing = res.scalar_one_or_none()
        if existing:
            print("EXISTS", existing.id)
        else:
            print("MISSING")
            u = User(
                email="admin@pqc.local",
                password_hash=hash_password("admin123"),
                role="admin",
                is_active=True,
            )
            s.add(u)
            await s.commit()
            await s.refresh(u)
            print("USER", u.id, u.email, u.role)

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
