(* EnergyQuestion.v — PUBLIC. The question, and nothing else.

   ClaimX b x l u : the FCIDUMP bytes b parse (Data layer: FCIDUMP.parse) to a file F, and the
   ground-state energy of F's Hamiltonian lies in [l/10^12, u/10^12] hartree, with u - l <= x.
   Which files are accepted is the Data layer's business; the question only asks about the file.

   The Hamiltonian is read straight from the parsed file's exact rational integrals
   (FCIDUMP.enuc, FCIDUMP.hcore, FCIDUMP.eri):
     H = E_core + sum_{pq,spin} h_pq a+_p a_q + 1/2 sum_{pqrs,spins} (pq|rs) a+_p a+_r a_s a_q
   on the determinants with nelec/2 electrons of each spin. A state is a vector w of whole numbers
   (a bound for all of them holds for every real vector); its energy is w^T H w / w^T w. *)
From Coq Require Import List ZArith QArith Ascii.
Require Import FCIDUMP_lib.
Import ListNotations.

Section Question.
Variable F : FCIDUMP.FCI.
Let n := FCIDUMP.norb F.

(* ---- the states: alpha string in the low n bits, beta string above; index I = alpha * NB + beta ---- *)
Fixpoint popc (m k : nat) : nat :=
  match k with O => O | S k' => ((if Nat.testbit m k' then 1 else 0) + popc m k')%nat end.
Definition strings : list nat :=
  filter (fun m => (popc m n =? FCIDUMP.nelec F / 2)%nat) (seq 0 (2 ^ n)).
Definition NB : nat := length strings.
Definition dim : nat := (NB * NB)%nat.
Definition st (I : nat) : nat := (nth (I / NB) strings 0 + 2 ^ n * nth (I mod NB) strings 0)%nat.

(* ---- creation (true, k) and annihilation (false, k) with Jordan-Wigner signs ---- *)
Fixpoint below (s p : nat) : nat :=
  match p with O => O | S p' => ((if Nat.testbit s p' then 1 else 0) + below s p')%nat end.
Definition jw (s p : nat) : Z := if Nat.even (below s p) then 1%Z else (-1)%Z.
Definition op1 (o : bool * nat) (x : option (Z * nat)) : option (Z * nat) :=
  match x with
  | None => None
  | Some (c, s) =>
      let '(dag, k) := o in
      if dag then (if Nat.testbit s k then None else Some ((c * jw s k)%Z, (s + 2 ^ k)%nat))
      else (if Nat.testbit s k then Some ((c * jw s k)%Z, (s - 2 ^ k)%nat) else None)
  end.
(* <t| w |s> for an operator word w, applied right to left *)
Definition amp (t : nat) (w : list (bool * nat)) (s : nat) : Z :=
  match fold_right op1 (Some (1%Z, s)) w with Some (c, s') => if (s' =? t)%nat then c else 0%Z | None => 0%Z end.

(* ---- the Hamiltonian; spin-orbital p + n*spin ---- *)
Definition so (p sg : nat) : nat := (p + n * sg)%nat.
Definition orbs := seq 0 n.
Definition spins := [0%nat; 1%nat].
Definition terms : list (Q * list (bool * nat)) :=
  flat_map (fun p => flat_map (fun q => map (fun sg =>
    (FCIDUMP.hcore F p q, [(true, so p sg); (false, so q sg)])) spins) orbs) orbs
  ++ flat_map (fun p => flat_map (fun q => flat_map (fun r => flat_map (fun s => flat_map (fun sg => map (fun tu =>
    ((1 # 2) * FCIDUMP.eri F p q r s, [(true, so p sg); (true, so r tu); (false, so s tu); (false, so q sg)]))
    spins) spins) orbs) orbs) orbs) orbs.
Definition H (I J : nat) : Q :=
  (if (I =? J)%nat then FCIDUMP.enuc F else 0)
  + fold_right Qplus 0 (map (fun x => fst x * inject_Z (amp (st I) (snd x) (st J))) terms).

(* ---- energies of whole-number states ---- *)
Fixpoint sumQ (k : nat) (f : nat -> Q) : Q := match k with O => 0 | S m => f O + sumQ m (fun i => f (S i)) end.
Definition quad (w : nat -> Z) : Q := sumQ dim (fun i => inject_Z (w i) * sumQ dim (fun j => H i j * inject_Z (w j))).
Definition dot (w : nat -> Z) : Q := sumQ dim (fun i => inject_Z (w i * w i)).
End Question.

(* ---- the question ---- *)
Definition ClaimX (b : list N) (x l u : Z) : Prop :=
  exists F, FCIDUMP.parse (FCIDUMP.to_ascii b) = Some F
    /\ (forall w, (l # 1) / (10 ^ 12 # 1) * dot F w <= quad F w)                    (* no state below lo *)
    /\ (exists w, 0 < dot F w /\ quad F w <= (u # 1) / (10 ^ 12 # 1) * dot F w)     (* a state at or below hi *)
    /\ (u - l <= x)%Z.                                                               (* precision *)
