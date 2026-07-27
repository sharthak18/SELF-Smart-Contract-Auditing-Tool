use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod safe_anchor {
    use super::*;
    pub fn safe_init(ctx: Context<SafeInit>) -> Result<()> { Ok(()) }
    pub fn safe_cpi(ctx: Context<SafeCpi>, amount: u64) -> Result<()> {
        let total = amount.checked_add(1).unwrap();
        ctx.accounts.vault.amount = total;
        ctx.accounts.vault.reload()?;
        invoke(&spl_token::ID, &[]);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SafeInit<'info> {
    #[account(init, payer = payer, space = 8)]
    pub vault: Account<'info, Vault>,
    #[account(signer)]
    pub payer: Signer<'info>,
    pub token_program: Program<'info, Token>,
    pub clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
pub struct SafeCpi<'info> {
    #[account(signer)]
    pub authority: Signer<'info>,
    pub vault: Account<'info, Vault>,
    #[account(address = spl_token::ID)]
    pub token_program: AccountInfo<'info>,
    #[account(has_one = authority)]
    pub pda: Account<'info, Pda>,
}

#[account]
pub struct Vault { pub amount: u64 }
#[account]
pub struct Pda { pub authority: Pubkey }
