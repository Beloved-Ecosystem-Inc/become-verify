From Coq Require Import ZArith NArith List.
Require Import FCIDUMP_lib.
Import ListNotations.
Definition pad_N (tail : list N) (t : N) : list N :=
  (tail ++ [128%N] ++ repeat 0%N (N.to_nat ((119 - t mod 64) mod 64)) ++ FCIDUMP.be_bytes 8 (8 * t))%list.
Lemma pad_N_ok : forall tail n, FCIDUMP.pad_final tail n = pad_N tail (N.of_nat n).
Proof.
  intros. unfold FCIDUMP.pad_final, pad_N. f_equal. f_equal. f_equal. f_equal.
  rewrite <- (Nat2N.id ((119 - n mod 64) mod 64)). f_equal.
  rewrite Nat2N.inj_mod, Nat2N.inj_sub, Nat2N.inj_mod. reflexivity.
Qed.
Definition len_N (full : list (list N)) (tail : list N) : N :=
  fold_left (fun a c => a + N.of_nat (List.length c))%N full (N.of_nat (List.length tail)).
Lemma len_N_ok : forall full tail, N.of_nat (FCIDUMP.total_len full tail) = len_N full tail.
Proof.
  intros. unfold FCIDUMP.total_len, len_N. generalize (List.length tail).
  induction full as [|c r IH]; intro n; simpl. reflexivity.
  rewrite IH, Nat2N.inj_add. reflexivity.
Qed.

(* Total length from per-chunk byte counts, without rewriting a large goal:
   the counts are supplied as a Forall2 proof built from each chunk's lemma. *)
Lemma len_N_fold : forall (full : list (list N)) (ns : list N) (acc : N),
  Forall2 (fun (c : list N) (n : N) => N.of_nat (List.length c) = n) full ns ->
  fold_left (fun a c => a + N.of_nat (List.length c))%N full acc = fold_left N.add ns acc.
Proof.
  intros full ns acc H. revert acc. induction H as [|c n full ns Hc H IH]; intros acc; simpl. reflexivity.
  rewrite Hc. apply IH.
Qed.
Lemma len_N_spec : forall (full : list (list N)) (tail ns : list N) (nt : N),
  Forall2 (fun (c : list N) (n : N) => N.of_nat (List.length c) = n) full ns -> N.of_nat (List.length tail) = nt ->
  len_N full tail = fold_left N.add ns nt.
Proof. intros full tail ns nt H Ht. unfold len_N. rewrite Ht. apply len_N_fold. assumption. Qed.

(* The SHA-256 state after all full chunks, from the per-chunk absorb lemmas.
   chain s cs s' says absorbing the chunks cs from state s ends in state s'. *)
Inductive chain : list N -> list (list N) -> list N -> Prop :=
| chain_nil : forall s, chain s [] s
| chain_cons : forall s c s1 cs s2, FCIDUMP.absorb s c = s1 -> chain s1 cs s2 -> chain s (c :: cs) s2.
Lemma chain_fold : forall s cs s', chain s cs s' -> fold_left FCIDUMP.absorb cs s = s'.
Proof. intros s cs s' H. induction H as [s|s c s1 cs s2 Hc H IH]; simpl. reflexivity. rewrite Hc. exact IH. Qed.
