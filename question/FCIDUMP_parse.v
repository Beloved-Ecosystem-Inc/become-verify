(* Records for the FCIDUMP integral lines, and the theorem that lets the whole-file parse
   be established chunk by chunk.

   A record holds one integral line exactly as written: the spaces before each of the five
   fields, the number (sign, integer part, optional fraction with its digit count so leading
   zeros are kept, optional exponent with its letter, sign and digit count) and the four
   indices. render prints a record back to the line's bytes.

   Each data chunk proves (by computation) that its records print back to exactly its bytes,
   with the partial lines carried across chunk boundaries, and that every record passes
   rec_ok: its printed text ends in a separator and tokenizes into five tokens that
   FCIDUMP's own number and index parsers accept. parse_records then gives the result of
   FCIDUMP.parse on the whole text: the header values and the list of entries, each entry
   being what FCIDUMP's parser reads from that record's own text (ival). The proofs below
   use only rec_ok, never the record layout, so they hold for any layout render can print. *)
From Coq Require Import ZArith NArith QArith List Lia.
Require Import Coq.Strings.String Coq.Strings.Ascii.
From Coq Require Uint63 PArray.
Require Import FCIDUMP_lib.
Import ListNotations.

Module RECS.

Record rec := mkrec {
  w0 : N; neg : bool; ip : N; dot : bool; fp : N; flen : N;
  ex : option (bool * N * N * N);          (* capital E?, sign (0 none, 1 -, 2 +), digit count, value *)
  w1 : N; ri : N; w2 : N; rj : N; w3 : N; rk : N; w4 : N; rl : N }.

Local Open Scope N_scope.
(* decimal digits of n as ASCII codes, most significant first; 0 prints as "0" *)
Fixpoint digits_acc (fuel : nat) (n : N) (acc : list N) : list N :=
  match fuel with
  | O => acc
  | S f => let acc' := (48 + n mod 10) :: acc in
           if n <? 10 then acc' else digits_acc f (n / 10) acc'
  end.
Definition digits (n : N) : list N := digits_acc 40 n [].
Definition padz (w : N) (l : list N) : list N := repeat 48 (N.to_nat w - List.length l) ++ l.
Definition spaces (w : N) : list N := repeat 32 (N.to_nat w).

Definition render (r : rec) : list N :=
  spaces (w0 r) ++ (if neg r then [45] else []) ++ digits (ip r) ++
  (if dot r then [46] ++ padz (flen r) (digits (fp r)) else []) ++
  match ex r with
  | None => []
  | Some (cap, sg, nd, v) =>
      [if cap then 69 else 101] ++ (if sg =? 1 then [45] else if sg =? 2 then [43] else []) ++ padz nd (digits v)
  end ++
  spaces (w1 r) ++ digits (ri r) ++ spaces (w2 r) ++ digits (rj r) ++
  spaces (w3 r) ++ digits (rk r) ++ spaces (w4 r) ++ digits (rl r) ++ [10].
Close Scope N_scope.

Definition renderA (r : rec) : list Ascii.ascii := FCIDUMP.to_ascii (render r).

(* Records are stored packed, 3 integers each (all below 2^63):
   a = fraction digits mod 2^62;
   b = fraction digits / 2^62 (4 bits) + 2^4 ip (20 bits) + 2^24 flen (5) + 2^29 neg + 2^30 dot
       + 2^31 (exponent present) + 2^32 (capital E) + 2^33 exponent sign (2) + 2^35 exponent
       digit count (2) + 2^37 exponent value (10);
   c = i + 2^8 j + 2^16 k + 2^24 l (8 bits each) + 2^32 w0 + 2^38 w1 + 2^44 w2 + 2^50 w3 + 2^56 w4
       (6 bits each). *)
Local Open Scope Z_scope.
Definition cellZ (arr : PArray.array Uint63.int) (k : Z) : Z := Uint63.to_Z (PArray.get arr (Uint63.of_Z k)).
Definition fld (x s w : Z) : N := Z.to_N ((x / 2 ^ s) mod 2 ^ w).
Definition bit (x s : Z) : bool := Z.eqb ((x / 2 ^ s) mod 2) 1.
Definition rec_of (a b c : Z) : rec :=
  {| w0 := fld c 32 6; neg := bit b 29; ip := fld b 4 20; dot := bit b 30;
     fp := Z.to_N (a + 2 ^ 62 * (b mod 16)); flen := fld b 24 5;
     ex := if bit b 31 then Some (bit b 32, fld b 33 2, fld b 35 2, fld b 37 10) else None;
     w1 := fld c 38 6; ri := fld c 0 8; w2 := fld c 44 6; rj := fld c 8 8;
     w3 := fld c 50 6; rk := fld c 16 8; w4 := fld c 56 6; rl := fld c 24 8 |}.
Fixpoint decode_from (arr : PArray.array Uint63.int) (n : nat) (k : Z) : list rec :=
  match n with
  | O => []
  | S n' => rec_of (cellZ arr k) (cellZ arr (k + 1)) (cellZ arr (k + 2)) :: decode_from arr n' (k + 3)
  end.
Definition decode (arr : PArray.array Uint63.int) (n : nat) : list rec := decode_from arr n 0.
Close Scope Z_scope.

(* What FCIDUMP's parser reads from one record's text. *)
Definition entry : Type := (Q * nat * nat * nat * nat)%type.
Definition rtoks (r : rec) : list (list Ascii.ascii) := FCIDUMP.toks (renderA r) [].
Definition ival_opt (r : rec) : option entry :=
  match rtoks r with
  | [v; i; j; k; l] =>
      match FCIDUMP.pnum v, FCIDUMP.pnat i, FCIDUMP.pnat j, FCIDUMP.pnat k, FCIDUMP.pnat l with
      | Some x, Some i', Some j', Some k', Some l' => Some (x, i', j', k', l')
      | _, _, _, _, _ => None
      end
  | _ => None
  end.
Definition ival (r : rec) : entry :=
  match ival_opt r with Some e => e | None => (0%Q, O, O, O, O) end.
Definition ends_sep (l : list Ascii.ascii) : bool :=
  match rev l with c :: _ => FCIDUMP.sep c | [] => false end.
Definition rec_ok (r : rec) : bool :=
  (ends_sep (renderA r) && match ival_opt r with Some _ => true | None => false end)%bool.

Fixpoint leqb (a b : list N) : bool :=
  match a, b with
  | [], [] => true
  | x :: a', y :: b' => (N.eqb x y && leqb a' b')%bool
  | _, _ => false
  end.
Lemma leqb_ok : forall a b, leqb a b = true -> a = b.
Proof.
  intros a. induction a as [|x a IH]; intros [|y b] H; simpl in H; try discriminate. reflexivity.
  apply andb_prop in H. destruct H as [H1 H2]. apply N.eqb_eq in H1. subst. f_equal. auto.
Qed.

(* The per-chunk checks, each run once by the kernel. *)
Definition chunk_ok (cin bytes cout : list N) (R : list rec) : bool :=
  (leqb (cin ++ bytes) (flat_map render R ++ cout) && forallb rec_ok R)%bool.
Definition chunk0_ok (hdr bytes cout : list N) (R : list rec) : bool :=
  (leqb bytes (hdr ++ flat_map render R ++ cout) && forallb rec_ok R)%bool.
Lemma chunk_ok_spec : forall cin bytes cout R, chunk_ok cin bytes cout R = true ->
  cin ++ bytes = flat_map render R ++ cout /\ forallb rec_ok R = true.
Proof. intros. apply andb_prop in H. destruct H as [H1 H2]. split; [apply leqb_ok |]; assumption. Qed.
Lemma chunk0_ok_spec : forall hdr bytes cout R, chunk0_ok hdr bytes cout R = true ->
  bytes = hdr ++ flat_map render R ++ cout /\ forallb rec_ok R = true.
Proof. intros. apply andb_prop in H. destruct H as [H1 H2]. split; [apply leqb_ok |]; assumption. Qed.

(* ---- joining chunks ---- *)
Inductive chainB : list N -> list (list N) -> list rec -> Prop :=
| cb_nil : chainB [] [] []
| cb_cons : forall cin c R cout cs Rs,
    cin ++ c = flat_map render R ++ cout -> chainB cout cs Rs -> chainB cin (c :: cs) (R ++ Rs).
Lemma chainB_concat : forall cin cs Rs, chainB cin cs Rs -> cin ++ List.concat cs = flat_map render Rs.
Proof.
  intros cin cs Rs H. induction H as [|cin c R cout cs Rs Hc H IH]. reflexivity.
  simpl. rewrite app_assoc, Hc, <- app_assoc, IH, flat_map_app. reflexivity.
Qed.
Lemma assemble : forall (hdr : list N) recs0 cout0 C Rs,
  cout0 ++ C = flat_map render Rs ->
  (hdr ++ flat_map render recs0 ++ cout0) ++ C = hdr ++ flat_map render (recs0 ++ Rs).
Proof. intros. rewrite flat_map_app, <- H, !app_assoc. reflexivity. Qed.
Lemma forallb_app_true : forall (f : rec -> bool) a b,
  forallb f a = true -> forallb f b = true -> forallb f (a ++ b) = true.
Proof. intros. rewrite forallb_app, H, H0. reflexivity. Qed.

(* ---- the parse of header ++ records ---- *)
Lemma ends_sep_cons : forall c l, l <> [] -> ends_sep (c :: l) = ends_sep l.
Proof.
  intros c l Hl. unfold ends_sep. simpl. destruct (rev l) as [|d r] eqn:E.
  - apply (f_equal (@rev _)) in E. rewrite rev_involutive in E. simpl in E. contradiction.
  - reflexivity.
Qed.

Lemma toks_app_sep : forall l1 l2 cur, ends_sep l1 = true ->
  FCIDUMP.toks (l1 ++ l2) cur = FCIDUMP.toks l1 cur ++ FCIDUMP.toks l2 [].
Proof.
  intros l1. induction l1 as [|c l1 IH]; intros l2 cur H. discriminate.
  destruct l1 as [|d l1'].
  - unfold ends_sep in H. simpl in H. simpl. rewrite H. destruct cur; reflexivity.
  - rewrite ends_sep_cons in H by discriminate.
    change ((c :: d :: l1') ++ l2) with (c :: ((d :: l1') ++ l2)).
    cbn [FCIDUMP.toks]. destruct (FCIDUMP.sep c).
    + destruct cur; rewrite IH by assumption; reflexivity.
    + rewrite IH by assumption. reflexivity.
Qed.

Lemma toks_flat : forall R, forallb rec_ok R = true ->
  FCIDUMP.toks (flat_map renderA R) [] = flat_map rtoks R.
Proof.
  intros R. induction R as [|r R IH]; intros H. reflexivity.
  simpl in H. apply andb_prop in H. destruct H as [Hr HR]. unfold rec_ok in Hr.
  apply andb_prop in Hr. destruct Hr as [He _].
  simpl. rewrite toks_app_sep by assumption. rewrite IH by assumption. reflexivity.
Qed.

Lemma rec_ok_toks : forall r, rec_ok r = true -> exists v i j k l x i' j' k' l',
  rtoks r = [v; i; j; k; l] /\ FCIDUMP.pnum v = Some x /\ FCIDUMP.pnat i = Some i' /\
  FCIDUMP.pnat j = Some j' /\ FCIDUMP.pnat k = Some k' /\ FCIDUMP.pnat l = Some l' /\
  ival r = (x, i', j', k', l').
Proof.
  intros r H. unfold rec_ok in H. apply andb_prop in H. destruct H as [_ H].
  unfold ival. unfold ival_opt in *.
  destruct (rtoks r) as [|v [|i [|j [|k [|l [|z rest]]]]]] eqn:E; try discriminate.
  destruct (FCIDUMP.pnum v) as [x|] eqn:Ex; [|discriminate].
  destruct (FCIDUMP.pnat i) as [i'|] eqn:Ei; [|discriminate].
  destruct (FCIDUMP.pnat j) as [j'|] eqn:Ej; [|discriminate].
  destruct (FCIDUMP.pnat k) as [k'|] eqn:Ek; [|discriminate].
  destruct (FCIDUMP.pnat l) as [l'|] eqn:El; [|discriminate].
  exists v, i, j, k, l, x, i', j', k', l'. repeat split; assumption || reflexivity.
Qed.

Lemma rtoks_length : forall R, forallb rec_ok R = true -> List.length (flat_map rtoks R) = (5 * List.length R)%nat.
Proof.
  intros R. induction R as [|r R IH]; intros H. reflexivity.
  simpl in H. apply andb_prop in H. destruct H as [Hr HR].
  destruct (rec_ok_toks r Hr) as (v & i & j & k & l & x & i' & j' & k' & l' & E & _).
  simpl. rewrite app_length, E, IH by assumption. simpl. lia.
Qed.

Lemma entries_ok : forall R fuel, forallb rec_ok R = true -> (List.length R < fuel)%nat ->
  FCIDUMP.entries fuel (flat_map rtoks R) = Some (map ival R).
Proof.
  intros R. induction R as [|r R IH]; intros fuel H Hf; (destruct fuel as [|f]; [simpl in Hf; lia|]).
  - reflexivity.
  - simpl in H. apply andb_prop in H. destruct H as [Hr HR].
    destruct (rec_ok_toks r Hr) as (v & i & j & k & l & x & i' & j' & k' & l' & E & Ex & Ei & Ej & Ek & El & Ev).
    simpl flat_map. rewrite E. cbn [app FCIDUMP.entries].
    rewrite Ex, Ei, Ej, Ek, El, IH by (simpl in Hf; (assumption || lia)).
    simpl map. rewrite Ev. reflexivity.
Qed.

Lemma key_app : forall k ts ts' v, FCIDUMP.key k ts = Some v -> FCIDUMP.key k (ts ++ ts') = Some v.
Proof.
  intros k ts. induction ts as [|t ts IH]; intros ts' v H. discriminate.
  cbn [app FCIDUMP.key] in *. destruct (FCIDUMP.prefix (FCIDUMP.str k) t) as [[|c cs]|].
  - destruct ts as [|t' ts]; [discriminate | exact H].
  - exact H.
  - apply IH. exact H.
Qed.

Definition has_end (ts : list (list Ascii.ascii)) : bool :=
  existsb (fun t => match FCIDUMP.prefix (FCIDUMP.str "&END") t with Some [] => true | _ => false end) ts.
Lemma after_end_app : forall ts ts', has_end ts = true ->
  FCIDUMP.after_end (ts ++ ts') = FCIDUMP.after_end ts ++ ts'.
Proof.
  intros ts. induction ts as [|t ts IH]; intros ts' H. discriminate.
  unfold has_end in H. cbn [existsb] in H. cbn [app FCIDUMP.after_end].
  destruct (FCIDUMP.prefix (FCIDUMP.str "&END") t) as [[|c cs]|]; cbn [orb] in H.
  - reflexivity.
  - apply IH. exact H.
  - apply IH. exact H.
Qed.

Definition header_val (k : String.string) (ts : list (list Ascii.ascii)) : option nat :=
  match FCIDUMP.key k ts with Some v => FCIDUMP.pnat v | None => None end.
Definition header_ok (HA : list Ascii.ascii) (n e m : nat) : bool :=
  let ts := FCIDUMP.toks HA [] in
  (ends_sep HA && has_end ts &&
   match FCIDUMP.after_end ts with [] => true | _ => false end &&
   match header_val "NORB=" ts with Some x => Nat.eqb x n | None => false end &&
   match header_val "NELEC=" ts with Some x => Nat.eqb x e | None => false end &&
   match header_val "MS2=" ts with Some x => Nat.eqb x m | None => false end &&
   negb (Nat.eqb (List.length ts) 0))%bool.

Lemma header_val_app : forall k ts ts' x, header_val k ts = Some x -> header_val k (ts ++ ts') = Some x.
Proof.
  intros k ts ts' x H. unfold header_val in *. destruct (FCIDUMP.key k ts) as [v|] eqn:E; [|discriminate].
  rewrite (key_app _ _ _ _ E). exact H.
Qed.

Theorem parse_records : forall HA R n e m,
  header_ok HA n e m = true -> forallb rec_ok R = true ->
  FCIDUMP.parse (HA ++ flat_map renderA R) =
  Some {| FCIDUMP.norb := n; FCIDUMP.nelec := e; FCIDUMP.ms2 := m; FCIDUMP.ints := map ival R |}.
Proof.
  intros HA R n e m H HR. unfold header_ok in H. cbv zeta in H.
  repeat (apply andb_prop in H; destruct H as [H ?]).
  rename H into Hsep.
  match goal with
  | Hn : (match header_val "NORB=" _ with _ => _ end) = true,
    He : (match header_val "NELEC=" _ with _ => _ end) = true,
    Hm : (match header_val "MS2=" _ with _ => _ end) = true,
    Ha : (match FCIDUMP.after_end _ with _ => _ end) = true,
    Hl : negb _ = true |- _ =>
      destruct (header_val "NORB=" (FCIDUMP.toks HA [])) as [xn|] eqn:En; [|discriminate];
      destruct (header_val "NELEC=" (FCIDUMP.toks HA [])) as [xe|] eqn:Ee; [|discriminate];
      destruct (header_val "MS2=" (FCIDUMP.toks HA [])) as [xm|] eqn:Em; [|discriminate];
      apply Nat.eqb_eq in Hn, He, Hm; subst xn xe xm;
      destruct (FCIDUMP.after_end (FCIDUMP.toks HA [])) eqn:Eae; [|discriminate];
      apply negb_true_iff, Nat.eqb_neq in Hl
  end.
  unfold FCIDUMP.parse. cbv zeta.
  rewrite toks_app_sep by assumption. rewrite toks_flat by assumption.
  pose proof (header_val_app _ _ (flat_map rtoks R) _ En) as Fn.
  pose proof (header_val_app _ _ (flat_map rtoks R) _ Ee) as Fe.
  pose proof (header_val_app _ _ (flat_map rtoks R) _ Em) as Fm.
  unfold header_val in Fn, Fe, Fm.
  destruct (FCIDUMP.key "NORB=" (FCIDUMP.toks HA [] ++ flat_map rtoks R)) as [vn|]; [|discriminate].
  destruct (FCIDUMP.key "NELEC=" (FCIDUMP.toks HA [] ++ flat_map rtoks R)) as [ve|]; [|discriminate].
  destruct (FCIDUMP.key "MS2=" (FCIDUMP.toks HA [] ++ flat_map rtoks R)) as [vm|]; [|discriminate].
  rewrite Fn, Fe, Fm.
  match goal with Hh : has_end _ = true |- _ => rewrite after_end_app by exact Hh end.
  rewrite Eae. simpl app.
  rewrite entries_ok by (assumption || (rewrite app_length, rtoks_length by assumption; lia)).
  reflexivity.
Qed.

Lemma map_flat_map_render : forall R,
  FCIDUMP.to_ascii (flat_map render R) = flat_map renderA R.
Proof.
  intros R. induction R as [|r R IH]. reflexivity.
  simpl. unfold FCIDUMP.to_ascii in *. rewrite map_app, IH. reflexivity.
Qed.

(* ===================== Well-formedness (format specification, rules 4-6) =====================
   Header: the header bytes equal the canonical header printed from NORB, NELEC, MS2, ORBSYM and
   ISYM, and these satisfy the electron and symmetry bounds. Content: the entries form three blocks
   in the order two-electron (all indices in 1..NORB), one-electron (i j 0 0, i and j in 1..NORB),
   core (0 0 0 0); keys in standard form strictly increase within each block (so no duplicates);
   exactly one core line, and it is last. Checked chunk by chunk with a small state machine. *)
Local Open Scope N_scope.
Definition lpad (w : nat) (l : list N) : list N := repeat 32 (w - List.length l) ++ l.
Definition dnat (x : nat) : list N := digits (N.of_nat x).
Definition header_canon (n e m : nat) (orb : list nat) (isym : nat) : list N :=
  [32; 38; 70; 67; 73; 32; 78; 79; 82; 66; 61] ++ lpad 4 (dnat n) ++     (* " &FCI NORB=" *)
  [44; 78; 69; 76; 69; 67; 61] ++ lpad 2 (dnat e) ++                     (* ",NELEC="     *)
  [44; 77; 83; 50; 61] ++ dnat m ++                                      (* ",MS2="       *)
  [44; 10; 32; 32; 79; 82; 66; 83; 89; 77; 61] ++                        (* ",\n  ORBSYM=" *)
  flat_map (fun o => dnat o ++ [44]) orb ++
  [10; 32; 32; 73; 83; 89; 77; 61] ++ dnat isym ++                       (* "\n  ISYM="   *)
  [44; 10; 32; 38; 69; 78; 68; 10].                                      (* ",\n &END\n"  *)
Close Scope N_scope.
Definition header_bounds (n e m : nat) (orb : list nat) (isym : nat) : bool :=
  (Nat.leb 1 n && Nat.leb n 255 && Nat.leb e (2 * n) && Nat.leb m e && Nat.even (e + m) &&
   Nat.leb ((e + m) / 2) n && Nat.eqb (List.length orb) n &&
   forallb (fun o => Nat.leb 1 o && Nat.leb o 8) orb && Nat.leb 1 isym && Nat.leb isym 8)%bool.

Definition inr (n a : nat) : bool := (Nat.leb 1 a && Nat.leb a n)%bool.
Definition pkey (a b : nat) : N :=
  if Nat.leb b a then (N.of_nat a * 256 + N.of_nat b)%N else (N.of_nat b * 256 + N.of_nat a)%N.
(* block (0 two-electron, 1 one-electron, 2 core) and key of an entry, or None if not allowed *)
Definition classify (n : nat) (en : entry) : option (nat * N) :=
  let '(_, i, j, k, l) := en in
  if (Nat.eqb i 0 && Nat.eqb j 0 && Nat.eqb k 0 && Nat.eqb l 0)%bool then Some (2%nat, 0%N)
  else if (inr n i && inr n j && Nat.eqb k 0 && Nat.eqb l 0)%bool then Some (1%nat, pkey i j)
  else if (inr n i && inr n j && inr n k && inr n l)%bool then
    let p := pkey i j in let q := pkey k l in
    Some (0%nat, if N.leb q p then (p * 65536 + q)%N else (q * 65536 + p)%N)
  else None.
Definition wstate : Type := (nat * N * bool)%type.            (* block, last key, core seen *)
Definition wstep (n : nat) (s : wstate) (en : entry) : option wstate :=
  let '(blk, last, core) := s in
  if core then None else
  match classify n en with
  | None => None
  | Some (b, key) =>
      if Nat.eqb b 2 then Some (2%nat, 0%N, true)
      else if Nat.ltb b blk then None
      else if Nat.eqb b blk then (if N.ltb last key then Some (b, key, false) else None)
      else Some (b, key, false)
  end.
Definition wrun (n : nat) (o : option wstate) (es : list entry) : option wstate :=
  fold_left (fun o en => match o with Some s => wstep n s en | None => None end) es o.
Lemma wrun_app : forall n o a b, wrun n o (a ++ b) = wrun n (wrun n o a) b.
Proof. intros. unfold wrun. apply fold_left_app. Qed.
Lemma wrun_chain : forall n o (A B : list rec) s r,
  wrun n o (map ival A) = Some s -> wrun n (Some s) (map ival B) = r -> wrun n o (map ival (A ++ B)) = r.
Proof. intros. rewrite map_app, wrun_app, H. exact H0. Qed.
Definition wf_ints (n : nat) (es : list entry) : bool :=
  match wrun n (Some (0%nat, 0%N, false)) es with Some (_, _, true) => true | _ => false end.

End RECS.
