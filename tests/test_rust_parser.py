"""Focused unit tests for the Rust/Anchor parser."""
import unittest

from self_tool.core.scanner import FileContext
from self_tool.parsers.rust_parser import parse_rust


def _ctx(src: str, name: str = "x.rs") -> FileContext:
    return FileContext(name, name, "rust", src)


PROGRAM = """
use anchor_lang::prelude::*;
declare_id!("11111111111111111111111111111111");
#[program]
pub mod m { use super::*; pub fn ix(ctx: Context<Ctx>, amount: u64) -> Result<()> { Ok(()) } }
"""


class AnchorParserTests(unittest.TestCase):
    def _struct(self, src: str, name: str):
        ctx = _ctx(PROGRAM + src)
        prog = parse_rust(ctx)
        self.assertTrue(prog.is_anchor)
        return prog.accounts_structs[name]

    def test_signer_constraint_on_accountinfo(self):
        s = self._struct(
            """
#[derive(Accounts)]
pub struct Ctx {
    #[account(signer)]
    pub authority: AccountInfo,
}
""", "Ctx")
        self.assertEqual(1, len(s.fields))
        f = s.fields[0]
        self.assertTrue(f.is_signer)
        self.assertTrue(f.is_unchecked)

    def test_typed_signer_is_recognised(self):
        s = self._struct(
            """
#[derive(Accounts)]
pub struct Ctx<'info> {
    pub payer: Signer<'info>,
}
""", "Ctx")
        self.assertTrue(s.fields[0].is_signer)
        self.assertFalse(s.fields[0].is_unchecked)

    def test_account_wrapper_marks_not_unchecked(self):
        s = self._struct(
            """
#[derive(Accounts)]
pub struct Ctx<'info> {
    pub vault: Account<'info, TokenAccount>,
}
""", "Ctx")
        self.assertFalse(s.fields[0].is_unchecked)
        self.assertTrue(s.fields[0].is_token_account)

    def test_program_account_is_program(self):
        s = self._struct(
            """
#[derive(Accounts)]
pub struct Ctx<'info> {
    pub token_program: Program<'info, Token>,
}
""", "Ctx")
        self.assertTrue(s.fields[0].is_program)

    def test_sysvar_is_sysvar(self):
        s = self._struct(
            """
#[derive(Accounts)]
pub struct Ctx<'info> {
    pub clock: Sysvar<'info, Clock>,
}
""", "Ctx")
        self.assertTrue(s.fields[0].is_sysvar)

    def test_seeds_and_canonical_bump(self):
        s = self._struct(
            """
#[derive(Accounts)]
pub struct Ctx<'info> {
    #[account(seeds = [b"vault", user.key().as_ref()], bump)]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}
""", "Ctx")
        f = s.fields[0]
        self.assertTrue(f.is_pda)
        self.assertEqual(["b\"vault\"", "user.key().as_ref()"], f.seeds)
        self.assertEqual("", f.bump)

    def test_explicit_bump_value(self):
        s = self._struct(
            """
#[derive(Accounts)]
pub struct Ctx<'info> {
    #[account(seeds = [b"v"], bump = my_bump)]
    pub vault: Account<'info, Vault>,
}
""", "Ctx")
        self.assertEqual("my_bump", s.fields[0].bump)

    def test_init_payer_space_captured(self):
        s = self._struct(
            """
#[derive(Accounts)]
pub struct Ctx<'info> {
    #[account(init, payer = u, space = 8 + 32)]
    pub v: Account<'info, Vault>,
    pub u: Signer<'info>,
}
""", "Ctx")
        f = s.fields[0]
        self.assertTrue(f.is_init)
        self.assertEqual("u", f.payer)
        self.assertIn("8", f.space)

    def test_init_if_needed_flag(self):
        s = self._struct(
            """
#[derive(Accounts)]
pub struct Ctx<'info> {
    #[account(init_if_needed, payer = u, space = 8)]
    pub v: Account<'info, Vault>,
    pub u: Signer<'info>,
}
""", "Ctx")
        self.assertTrue(s.fields[0].is_init_if_needed)

    def test_realloc_payer_captured(self):
        s = self._struct(
            """
#[derive(Accounts)]
pub struct Ctx<'info> {
    #[account(realloc = 64, realloc::payer = u, realloc::zero = false)]
    pub v: Account<'info, Vault>,
    pub u: Signer<'info>,
}
""", "Ctx")
        f = s.fields[0]
        self.assertEqual("64", f.realloc)
        self.assertEqual("u", f.realloc_payer)
        self.assertEqual("false", f.realloc_zero)

    def test_has_one_owner_address_constraints(self):
        s = self._struct(
            """
#[derive(Accounts)]
pub struct Ctx<'info> {
    #[account(has_one = authority, owner = token_program, address = fixed)]
    pub v: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
""", "Ctx")
        f = s.fields[0]
        self.assertEqual(["authority"], f.has_one)
        self.assertEqual("token_program", f.owner)
        self.assertEqual("fixed", f.address)

    def test_instruction_cpi_args_captured(self):
        ctx = _ctx("""
use anchor_lang::prelude::*;
declare_id!("11111111111111111111111111111111");
#[program]
pub mod m {
    use super::*;
    pub fn ix(ctx: Context<C>) -> Result<()> {
        invoke(&ix, &[]);
        invoke_signed(&si, &[], &[&[b"seed", &[bump]]]);
        Ok(())
    }
}
#[derive(Accounts)]
pub struct C {}
""")
        prog = parse_rust(ctx)
        instr = prog.instructions[0]
        self.assertTrue(instr.has_cpi)
        self.assertEqual(["&ix", "&si"], instr.cpi_program_args)

    def test_instruction_checked_arith_count(self):
        ctx = _ctx("""
use anchor_lang::prelude::*;
declare_id!("11111111111111111111111111111111");
#[program]
pub mod m {
    use super::*;
    pub fn safe_ix(ctx: Context<C>, a: u64, b: u64) -> Result<()> {
        let _ = a.checked_add(b).unwrap();
        let _ = b.checked_sub(a).unwrap();
        Ok(())
    }
    pub fn unsafe_ix(ctx: Context<C>, a: u64, b: u64) -> Result<()> {
        let _ = a + b;
        let _ = b - a;
        let _ = a * b;
        Ok(())
    }
}
#[derive(Accounts)]
pub struct C {}
""")
        prog = parse_rust(ctx)
        safe, unsafe = prog.instructions
        self.assertEqual(0, safe.unchecked_arith_ops)
        self.assertGreater(safe.checked_arith_ops, 0)
        self.assertGreaterEqual(unsafe.unchecked_arith_ops, 3)
        self.assertEqual(0, unsafe.checked_arith_ops)


if __name__ == "__main__":
    unittest.main()