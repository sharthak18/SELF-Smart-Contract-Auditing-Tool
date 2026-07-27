// Vulnerable Anchor program — mirrors 5 known Solana exploit classes.
// Used to test SELF's Rust/Anchor detectors.
//
// Bugs intentionally embedded:
//   1. `initialize` — missing Signer check on `authority: AccountInfo`
//   2. `withdraw` — arbitrary CPI to attacker-controlled program
//   3. `claim` — PDA seeds without bump verification
//   4. `close_pool` — `close = pool` drains lamports back to attacker
//   5. `swap` — unchecked arithmetic (wraps in release build)
//   6. `flash_loan` — account reloaded after CPI, but balance read first

use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

declare_id!("Vuln111111111111111111111111111111111111111");

pub mod vulnerable {
    use super::*;

    pub fn log_balance(ctx: Context<LogBalance>) -> Result<()> {
        let bal = ctx.accounts.vault.amount;
        msg!("balance: {}", bal);
        Ok(())
    }
}

#[program]
pub mod vulnerable_anchor {
    use super::*;

    // BUG 1: `authority: AccountInfo` is not Signer. Anyone can pass
    // any account as authority and become the owner.
    pub fn initialize(ctx: Context<Initialize>, fee_bps: u16) -> Result<()> {
        ctx.accounts.pool.authority = ctx.accounts.authority.key();
        ctx.accounts.pool.fee_bps = fee_bps;
        Ok(())
    }

    // BUG 2: invoke() without validating token_program.key() == spl_token::ID.
    // Attacker passes their own program as the CPI target.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let ix = spl_token::instruction::transfer(
            ctx.accounts.token_program.key,
            ctx.accounts.vault.to_account_info().key,
            ctx.accounts.destination.key,
            ctx.accounts.authority.key,
            &[],
            amount,
        )?;
        invoke(
            &ix,
            &[
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.destination.to_account_info(),
                ctx.accounts.authority.clone(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;
        Ok(())
    }

    // BUG 3: PDA seeds without bump verification — non-canonical bump
    // leads to account substitution.
    pub fn claim(ctx: Context<Claim>, amount: u64) -> Result<()> {
        let (pda, _bump) = Pubkey::find_program_address(
            &[b"vault", ctx.accounts.user.key.as_ref()],
            ctx.program_id,
        );
        // No bump check against the canonical bump stored in account data.
        ctx.accounts.vault.balance = ctx.accounts.vault.balance - amount;
        Ok(())
    }

    // BUG 4: missing Owner check on `pool: AccountInfo` — attacker can
    // pass a fake pool owned by their program.
    pub fn close_pool(ctx: Context<ClosePool>) -> Result<()> {
        // Anchor requires Account<> for ownership; this raw AccountInfo bypasses it.
        let pool = &ctx.accounts.pool;
        pool.close(ctx.accounts.destination.to_account_info())?;
        Ok(())
    }

    // BUG 5: unchecked arithmetic — overflow wraps in release builds.
    pub fn swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
        let total = ctx.accounts.pool.balance + amount;
        ctx.accounts.pool.balance = total;
        Ok(())
    }

    // BUG 6: account `vault` read after CPI without reload.
    pub fn flash_loan(ctx: Context<FlashLoan>, amount: u64) -> Result<()> {
        let bal_before = ctx.accounts.vault.amount;
        let ix = spl_token::instruction::transfer(
            ctx.accounts.token_program.key,
            ctx.accounts.vault.to_account_info().key,
            ctx.accounts.destination.key,
            ctx.accounts.pool_authority.key,
            &[],
            amount,
        )?;
        invoke(
            &ix,
            &[
                ctx.accounts.vault.to_account_info(),
                ctx.accounts.destination.to_account_info(),
                ctx.accounts.pool_authority.clone(),
                ctx.accounts.token_program.to_account_info(),
            ],
        )?;
        // BUG: reads ctx.accounts.vault.amount (stale) without reload.
        msg!("balance after CPI: {}", ctx.accounts.vault.amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    pub authority: AccountInfo<'info>,        // BUG: should be Signer
    #[account(init, payer = payer, space = 8 + 64)]
    pub pool: Account<'info, Pool>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub authority: Signer<'info>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub destination: AccountInfo<'info>,      // BUG: should be Account<>
    /// CHECK: token program — no owner check
    pub token_program: AccountInfo<'info>,    // BUG: should be Program<>
}

#[derive(Accounts)]
pub struct Claim<'info> {
    pub user: Signer<'info>,
    // BUG: seeds + bump not required for canonical-bump verification
    #[account(seeds = [b"vault", user.key.as_ref()], bump)]
    pub vault: Account<'info, Vault>,
}

#[derive(Accounts)]
pub struct ClosePool<'info> {
    #[account(mut)]
    pub pool: AccountInfo<'info>,             // BUG: should be Account<>, missing owner check
    #[account(mut)]
    pub destination: Signer<'info>,
}

#[derive(Accounts)]
pub struct Swap<'info> {
    pub user: Signer<'info>,
    #[account(mut)]
    pub pool: Account<'info, Pool>,
}

#[derive(Accounts)]
pub struct FlashLoan<'info> {
    pub pool_authority: Signer<'info>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub destination: AccountInfo<'info>,
    pub token_program: AccountInfo<'info>,    // BUG: should be Program<Token>
    #[account(mut)]
    pub pool: Account<'info, Pool>,
}

#[derive(Accounts)]
pub struct LogBalance<'info> {
    pub vault: Account<'info, TokenAccount>,
}

#[account]
pub struct Pool {
    pub authority: Pubkey,
    pub fee_bps: u16,
    pub balance: u64,
}

#[account]
pub struct Vault {
    pub balance: u64,
}
