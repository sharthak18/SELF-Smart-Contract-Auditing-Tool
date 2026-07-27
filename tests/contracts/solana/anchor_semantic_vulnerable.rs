use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod semantic_anchor {
    use super::*;
    pub fn unsafe_init(ctx: Context<UnsafeInit>) -> Result<()> { Ok(()) }
    pub fn unsafe_cpi(ctx: Context<UnsafeCpi>) -> Result<()> {
        invoke(&ix, &[]);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct UnsafeInit<'info> {
    #[account(init_if_needed, space = 8)]
    pub vault: AccountInfo<'info>,
    pub authority: AccountInfo<'info>,
    pub token_program: AccountInfo<'info>,
    pub clock: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct UnsafeCpi<'info> {
    pub program: AccountInfo<'info>,
    #[account(seeds = [b"vault"])]
    pub pda: AccountInfo<'info>,
}
